{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

{-
 - Copyright: 2026 Chris Misa
 - License: (See ./LICENSE)
 -
 - Entry point for running various multifractal analysis of IP address space data.
 -
 -}


{-

v6 port considerations.

1. Have to actually implement the min prefix length idea based on IANA data. (default to largest / smallest allocation for now: /12 or /23)
2. Have to establish some default max prefix length in case auto-stop fails.
3. All the places where Word32 is used as an address
4. Add flag for v6 vs v4 input
5. filterValidPrefixes and other functions


Other book keeping:

remove the post filter multinomialFit?
make dump of per-pl tau estimates an output option not a metadata thing?

-}

module MAAD where

import System.Environment
import System.Exit
import System.IO
import Data.Function ((&))
import Control.Arrow
import Control.Monad

import Data.Word
import Data.Bits
import Data.Maybe

import qualified Data.List as L

import Data.Aeson ((.=), Value, encode, object)
import qualified Data.ByteString.Char8 as B
import Data.ByteString.Char8 (ByteString)
import qualified Data.ByteString.Lazy.Char8 as BL8

import Options.Applicative -- optparse-applicative

import qualified Data.Vector.Unboxed as VU
import qualified Statistics.Sample as SS
import qualified Statistics.Regression as Reg

import Data.TreeFold (treeFold)

import Data.HashMap.Strict (HashMap)
import qualified Data.HashMap.Strict as HM

import qualified Numeric.LinearAlgebra as LA
import Statistics.Distribution.FDistribution (fDistribution)
import Statistics.Distribution.Normal (normalDistr)
import Statistics.Distribution (cumulative)

import Data.WideWord.Word128

-- Local imports
import Common
import PrefixMap (Addr(..), Prefix(..), PrefixMap)
import qualified PrefixMap as PM

defaultFullThreshold :: Double
defaultFullThreshold = 0.05

defaultAutoStopThreshold :: Double
defaultAutoStopThreshold = 0.001

defaultMinPrefixLength4 :: Int
defaultMinPrefixLength4 = 8

defaultMaxPrefixLength4 :: Int
defaultMaxPrefixLength4 = 24

defaultMinPrefixLength6 :: Int
defaultMinPrefixLength6 = 23

defaultMaxPrefixLength6 :: Int
defaultMaxPrefixLength6 = 64

deltaQ :: Double
deltaQ = 1.0 / 16.0

-- Min q based on theoretic range of normalicy of tauTilde(q)
minQ :: Double
minQ = -1.0 / 2.0

-- Max q based on theoretic range of convergence of tauTilde(q) because it's less sensitive in the Legendre transform
maxQ :: Double
maxQ = 3.5

qs :: [Double]
qs = [minQ, minQ+deltaQ..maxQ]

data OutputFormat = OutputCsv | OutputJson
  deriving (Eq, Show)

data Config = Config
  { cfgFilepath :: String
  , cfgOutPrefix :: String
  , cfgFormat :: OutputFormat
  , cfgStructure :: Bool
  , cfgSpectrum :: Bool
  , cfgDimensions :: Bool
  , cfgPartitions :: Bool
  , cfgSingularities :: Bool
  , cfgWeights :: Bool
  , cfgTest :: Bool
  , cfgTestFile :: Maybe String
  , cfgTestFileIsStructure :: Bool
  , cfgV6 :: Bool
  , cfgCsv :: Bool
  , cfgAddrCol :: Maybe Int
  , cfgMeasureCol :: Maybe Int
  , cfgSkipFirst :: Bool
  , cfgFullThresh :: Double
  , cfgAutoStop :: Bool
  , cfgBTarget :: Double
  , cfgForceMinPrefixLength :: Maybe Int
  , cfgForceMaxPrefixLength :: Maybe Int
  , cfgPrefixLengths :: [Int]
  }
  deriving (Show)

requestedAnalysisCount :: Config -> Int
requestedAnalysisCount conf =
  [ cfgStructure
  , cfgSpectrum
  , cfgDimensions
  , cfgPartitions
  , cfgSingularities
  , cfgWeights
  , cfgTest
  , isJust . cfgTestFile
  ]
  & fmap (\f -> if f conf then 1 else 0)
  & foldl1 (+)

data Metadata = Metadata
  { metaInput :: String
  , metaMinPrefixLength :: Int
  , metaMaxPrefixLength :: Int
  , metaTotalAddrs :: Int
  , metaDidAutoStop :: Maybe Int
  , metaPreFilterPrefixCounts :: [(Int, Int)]
  , metaPrefixCounts :: [(Int, Int)]
  , metaMultinomialFits :: [(Double, Double, Double)]
  , metaPerPrefixLengthVars :: [(Int, Double, Double, Double)]
  , metaCriticalRegion :: (Double, Double)
  }

data Results = Results
  { resStructure :: Maybe [(Double, Double, Double)]
  , resSpectrum :: Maybe [(Double, Double)]
  , resDimensions :: Maybe [(Double, Double, Double)]
  , resPartitions :: Maybe [(Double, [(Double, Double)])]
  , resSingularities :: Maybe [(Double, (Addr, Double, Double, Int))]
  , resWeights :: Maybe [(Int, Addr, Double, Double, Double)]
  , resTest :: Maybe CompareResult
  , resCompare :: Maybe CompareResult
  }

data CompareResult = CompareResult
  { crPValue :: Double
  , crDelta2 :: Double
  , crN :: Double
  , crM :: Double
  , crP :: Double
  , crNumBaselineAddrs :: Int
  , crNumTestAddrs :: Int
  }

parseOutputFormat :: String -> Either String OutputFormat
parseOutputFormat "csv" = Right OutputCsv
parseOutputFormat "json" = Right OutputJson
parseOutputFormat _ = Left "FORMAT must be one of: csv, json"

formatName :: OutputFormat -> String
formatName OutputCsv = "csv"
formatName OutputJson = "json"

optparser :: Parser Config
optparser = Config
  <$> strOption ( long "input"
                  <> metavar "FILEPATH"
                  <> help "File to read (csv or one address on each line)."
                )
  <*> strOption ( long "output"
                  <> metavar "OUT_PREFIX"
                  <> help "Prefix for output files (for FORMAT = csv), output file (for FORMAT = json), or - for stdout."
                )
  <*> option (eitherReader parseOutputFormat) ( long "format"
                                                <> metavar "FORMAT"
                                                <> value OutputCsv
                                                <> showDefaultWith formatName
                                                <> help "Output format: csv or json."
                                              )
  <*> switch ( long "structure" <> short 't'
               <> help "Compute structure function (OUT_PREFIX_structure.csv)."
             )
  <*> switch ( long "spectrum" <> short 's'
               <> help "Compute multifractal spectrum (OUT_PREFIX_spectrum.csv)."
             )
  <*> switch ( long "dimensions" <> short 'd'
               <> help "Compute generalized dimensions (OUT_PREFIX_dimensions.csv)."
             )
  <*> switch ( long "partitions" <> short 'p'
               <> help "Compute partition functions (OUT_PREFIX_partitions.csv). (Note that this uses a different range of q values than the other estimates.)"
             )
  <*> switch ( long "singularities" <> short 'e'
               <> help "Compute the singularities or Hölder exponents estimated at each IP address."
             )
  <*> switch ( long "weights" <> short 'w'
               <> help "Compute the weights at each node in the prefix tree."
             )
  <*> switch ( long "test"
               <> help "Test if the structure function is non-linear. Uses the same method as --compare, but compares against an imaginary structure function that's just a linear interpolation of the estimated structure function between the min and max q-values."
             )
  <*> optional (strOption ( long "compare" <> metavar "FILEPATH2"
                            <> help "Perform Hotelling's t^2 test of the null hypothesis that the addresses in FILEPATH2 come from the same distribution as the addresses in FILEPATH (using the structure function). Assumes that FILEPATH2 follows the same line format as FILEPATH (e.g., csv or raw list of addresses, etc.)."
                            ))
  <*> switch ( long "compare-structure"
               <> help "If set, assume FILEPATH2 (used by --compare) contains the already-computed structure function (in csv format as output by MAAD with the same q-values) instead of a raw set of addresses. Useful for pre-computing the structure function to compare against or comparing against theoretical structure functions. (Assumes 9 prefix lengths were used.)"
             )
  <*> switch ( long "ipv6" <> short '6'
               <> help "Input file contains IPv6 addresses instead of IPv4 addresses (the default)."
             )
  <*> switch ( long "csv"
               <> help "Input file is csv (with multiple columns that need to be parsed)."
             )
  <*> optional (option auto ( long "addr-col" <> metavar "COL" <> short 'a'
                              <> help "If input is a csv file, this (zero-based) column contains the IP addresses to analyze. Default to column 0."
                            ))
  <*> optional (option auto ( long "meas-col" <> metavar "COL" <> short 'm'
                              <> help "If the input is a csv file, this (zero-based) column contains the measure associated with each IP address. If not specified, each address will receive constant measure 1.0 (even if --csv is specified)."))
  <*> switch ( long "skip-first"
               <> help "Skip the first (header) row before reading the data."
             )
  <*> option auto ( long "full-threshold" <> metavar "C"
                    <> value defaultFullThreshold <> showDefault
                    <> help "Threshold for determining nearly-full prefixes (based on how close log_2(mu) is to capacity at prefix length)."
                  )
  <*> switch ( long "auto-stop" <> help "Automatically stop reading addresses when the maximum estimated CI around counts at the (estimated) maximum significant prefix length is less than B_TARGET."
             )
  <*> option auto ( long "b-target" <> metavar "B_TARGET" <> value defaultAutoStopThreshold <> showDefault
                  <> help "The target CI width used if auto-stop is enabled."
                  )
  <*> optional (option auto ( long "force-min-prefix-length" <> metavar "MIN_LEN"
                            <> help "Override automatic determination of minimum prefix length."
                            ))
  <*> optional (option auto ( long "force-max-prefix-length" <> metavar "MAX_LEN"
                            <> help "Override automatic determination of maximum prefix length."
                            ))
  <*> pure []

opts :: ParserInfo Config
opts = info (optparser <**> helper)
  ( fullDesc
    <> progDesc "Compute a combination of different multifractal analyses of a given set of IP addresses, optimally based on a per-address measure."
    <> header "MAAD - Multifractal Address-space Anomaly Detection"
  )

dieWith :: String -> IO ()
dieWith msg = hPutStrLn stderr msg >> exitFailure

main :: IO ()
main = do
  conf <- execParser opts

  -- Verify that the configuration given in the arguments is valid
  when (requestedAnalysisCount conf <= 0) $
    dieWith "Must specify one of --structure, --spectrum, --dimensions, --partitions, --singularities, --weights, --test, or --compare to compute."
    
  when ((isJust (cfgAddrCol conf) || isJust (cfgMeasureCol conf)) && not (cfgCsv conf)) $
    dieWith "To specify --addr-col or --meas-col, you must also indicate the input is a csv file by specifying --csv"

  when (cfgOutPrefix conf == "-" && cfgFormat conf == OutputCsv && requestedAnalysisCount conf > 1) $
    dieWith "CSV stdout only supports a single requested analysis; use --format json or a file prefix."

  -- Run with verified configuration
  run conf

{-
 - Run analysis and write results as described by the given configuration.
 -}
run :: Config -> IO ()
run conf = do

  (pfxs, didAutoStop) <- loadAddresses conf (cfgFilepath conf)

  (validLengths, validPfxs, preFilterPrefixCounts) <- buildValidPrefixes conf pfxs didAutoStop

  let conf' = conf { cfgPrefixLengths = validLengths }

      (taus, perPrefixLengthVars) = computeTauTilde conf' validPfxs

      criticalRegion = computeCriticalRegion taus

      -- TDOD add an option so we output per-prefix results only if asked for... 
  
      -- Compute the metadata
      metadata = Metadata
        { metaInput = cfgFilepath conf'
        , metaMinPrefixLength = foldl1 min (cfgPrefixLengths conf')
        , metaMaxPrefixLength = foldl1 max (cfgPrefixLengths conf')
        , metaTotalAddrs = length (PM.leaves pfxs)
        , metaDidAutoStop = didAutoStop
        , metaPreFilterPrefixCounts = preFilterPrefixCounts
        , metaPrefixCounts = fmap (second (HM.size . fst)) (cfgPrefixLengths conf' `zip` validPfxs)
        , metaMultinomialFits = fmap (multinomialFit conf') (cfgPrefixLengths conf' `zip` fmap fst validPfxs)
        , metaPerPrefixLengthVars = perPrefixLengthVars
        , metaCriticalRegion = criticalRegion
        }

  
      -- Compute what was requested
      structureRows = if cfgStructure conf' then Just (VU.toList taus) else Nothing
      spectrumRows = if cfgSpectrum conf' then Just (computeSpectrumRows taus criticalRegion) else Nothing
      dimensionRows = if cfgDimensions conf' then Just (computeDimensionRows conf' taus pfxs) else Nothing
      partitionsRows = if cfgPartitions conf' then Just (computePartitions conf' pfxs) else Nothing
      singularitiesRows = if cfgSingularities conf' then Just (computeSingularities conf' pfxs) else Nothing
      weightsRows = if cfgWeights conf' then Just (computeWeights conf' validLengths validPfxs) else Nothing
  testResult <- if cfgTest conf' then fmap Just (computeT2TestInterpolateSelf conf' taus (length $ PM.leaves pfxs)) else return Nothing
  compareResult <- case cfgTestFile conf' of
    Just testfile -> fmap Just (computeT2Test conf' testfile taus (length $ PM.leaves pfxs))
    Nothing -> return Nothing

  -- Write output to csv files, std out, or json
  emitResults conf' metadata $ Results
    { resStructure = structureRows
    , resSpectrum = spectrumRows
    , resDimensions = dimensionRows
    , resPartitions = partitionsRows
    , resSingularities = singularitiesRows
    , resWeights = weightsRows
    , resTest = testResult
    , resCompare = compareResult
    }



computeWeights :: Config
               -> [Int]
               -> [(HashMap Prefix Double, HashMap Prefix Double)]
               -> [(Int, Addr, Double, Double, Double)]
computeWeights conf pls pfxs =
  let onePl (pl, (thisPl, nextPl)) = thisPl
        & HM.toList
        & fmap (\(pfx, mu) ->
                  let addr = PM.prefixToAddress pfx
                      [leftChild, rightChild] = PM.children pfx
                      left = HM.lookupDefault 0.0 leftChild nextPl
                      -- for sanity checking, also compute the right weight manually like this
                      right = HM.lookupDefault 0.0 rightChild nextPl
                  in (pl, addr, mu, left / mu, right / mu)
               )
  in concatMap onePl (pls `zip` pfxs)

{-
 - Load addresses from file using parameters specified in the configuration
 -}
loadAddresses :: Config -> String -> IO (PrefixMap Double, Maybe Int)
loadAddresses conf filepath = do
  let extractSingleAddr :: [ByteString] -> ByteString
      extractSingleAddr (addr:_) = addr
      extractSingleAddr [] = error "Expected at least one column in each input row"

  -- Load in the addresses and optional associated "weights"
  let autoStopConf = case cfgAutoStop conf of
          True -> Just (cfgBTarget conf)
          False -> Nothing

  if cfgCsv conf
    then let extract_addr = flip (!!) (fromMaybe 0 (cfgAddrCol conf)) -- default to column 0
             extract_meas =
               case cfgMeasureCol conf of
                 Just col -> read . B.unpack . flip (!!) col
                 Nothing -> const 1.0 -- default to constant 1.0 for each address
         in PM.fromFile filepath (cfgV6 conf) (cfgSkipFirst conf) autoStopConf extract_addr extract_meas
    else PM.fromFile filepath (cfgV6 conf) (cfgSkipFirst conf) autoStopConf extractSingleAddr (const 1.0)

{-
 - Figure out prefix length range and build list of valid prefixes (and next-child prefixes) at each prefix length.
 -
 - In IO because it might need to print some warnings...
 -}
buildValidPrefixes :: Config
                   -> PrefixMap Double
                   -> Maybe Int
                   -> IO ([Int], [(HashMap Prefix Double, HashMap Prefix Double)], [(Int, Int)])
buildValidPrefixes conf pfxs didAutoStop = do
  let minPrefixLength = case cfgForceMinPrefixLength conf of
        Just pl -> pl
        Nothing -> case PM.prefixMapVersion pfxs of
          Addr4 _ -> defaultMinPrefixLength4
          Addr6 _ -> defaultMinPrefixLength6
  let maxPrefixLength = case cfgForceMaxPrefixLength conf of
        Just pl -> pl
        Nothing -> case didAutoStop of
          Just autoStopPl -> autoStopPl
          Nothing -> case PM.prefixMapVersion pfxs of
            Addr4 _ -> defaultMaxPrefixLength4
            Addr6 _ -> defaultMaxPrefixLength6

  hPutStrLn stderr $ "Min prefix length: " ++ show minPrefixLength
  hPutStrLn stderr $ "Max prefix length: " ++ show maxPrefixLength
  when (minPrefixLength >= maxPrefixLength) (error "Invalid prefix length range. If this happens automatically, consider overriding prefix length range with --force-min-prefix-length and --force-max-prefix-length")
  
  let initialPrefixLengths = [minPrefixLength .. maxPrefixLength]

      -- Compute pre-filter per-prefix-length counts
      preFilterPrefixCounts :: [(Int, Int)]
      preFilterPrefixCounts = [(pl, length $ PM.leaves $ PM.sliceAtLength pl pfxs) | pl <- initialPrefixLengths]
  
      -- Compute the sets of prefixes at each length with valid scaling behavior
      validPfxsEmpties :: [(HashMap Prefix Double, HashMap Prefix Double)]
      validPfxsEmpties = fmap (filterValidPrefixes conf pfxs) initialPrefixLengths

      -- Filter out prefix lengths where there are actually zero valid prefixes
      validPfxsLengths = zip initialPrefixLengths validPfxsEmpties
                         & filter ((> 0) . HM.size . fst . snd)

      validLengths = fmap fst validPfxsLengths
      validPfxs = fmap snd validPfxsLengths

  -- Warn if we filtered any prefix lengths due to zero valid prefixes
  when (length validPfxsEmpties /= length validPfxs) $ do
    hPutStrLn stderr $ "WARNING: dropping the following prefix lengths because they had no valid prefixes:" ++ show (initialPrefixLengths & filter (not . flip elem validLengths))

  return (validLengths, validPfxs, preFilterPrefixCounts)


{-
 - Filters the prefix map to remove atomic and nearly-full prefixes at pl.
 - Returns maps for the valid prefixes at pl and their children at pl + 1
 -}
filterValidPrefixes :: Config -> PrefixMap Double -> Int -> (HashMap Prefix Double, HashMap Prefix Double)
filterValidPrefixes conf pm pl =
  let removeAtomicAndFull count pfx _ =
        let pl' = PM.prefixLength pfx
            maxPl = PM.maxPrefixLength pfx
            delta = cfgFullThresh conf
        in count > 1 && logBase 2 (fromIntegral count) / fromIntegral (maxPl - pl') < 1.0 - delta
        
      thisPl = pm
        & PM.sliceAtLength pl
        & PM.filterCount removeAtomicAndFull
        & PM.leaves
        & filter ((== pl) . PM.prefixLength . fst) -- catch any leaves shorter than pl that filterCount might have left in
        & HM.fromList

      nextPl = pm
        & PM.sliceAtLength (pl + 1)
        & PM.leaves
        & filter ((`HM.member` thisPl) . (flip PM.preserve_upper_bits pl) . fst)
        & HM.fromList
        
  in (thisPl, nextPl)


{-
 - Computes the tauTilde estimator using the given prefix lengths and per-prefix-length maps
 - Returns both the averaged tauTilde vs. q result as well as the per-prefix-length estimates
 -}
computeTauTilde :: Config -> [(HashMap Prefix Double, HashMap Prefix Double)] -> (VU.Vector (Double, Double, Double), [(Int, Double, Double, Double)])
computeTauTilde conf validPfxs =

  -- Compute tauTilde at each prefix length, each value of q
  let allMoments :: [(Double, [(Double, Double)])]
      allMoments = [(q, [oneMoment conf q pfxs | pfxs <- validPfxs]) | q <- qs]


      -- Compute the structure function from all tauTildes
      oneTau (q, moms) = 
        let n = fromIntegral (length moms)
            tauTilde = moms
              & fmap fst
              & VU.fromList
              & SS.mean
            sd = moms
              & fmap snd
              & treeFold (+) 0.0
              & ((/ n) . sqrt)
        in (q, tauTilde, sd)

      taus = allMoments & fmap oneTau & VU.fromList

      -- Just dump all the per-prefix-length variances and summarize later
      perPrefixLengthVars :: [(Int, Double, Double, Double)]
      perPrefixLengthVars =
        [ (pl, q, tau, v) | (q, moms) <- allMoments, (pl, (tau, v)) <- (cfgPrefixLengths conf `zip` moms)]
  in (taus, perPrefixLengthVars)

{-
 - Load the addresses in testfile and just compute and return their tauTildes and sds
 - As a utility for computeT2Test
 -}
tausFromAddressFile :: Config -> String -> IO (VU.Vector (Double, Double, Double), Double, Int)
tausFromAddressFile conf testfile = do
  (testPfxs, testAutoStopped) <- loadAddresses conf testfile
  
  (testLengths, testPfxsValid, _) <- buildValidPrefixes conf testPfxs testAutoStopped

  let (testTaus, _) = computeTauTilde (conf { cfgPrefixLengths = testLengths }) testPfxsValid
      m = fromIntegral $ length testLengths
      nTestAddrs = length $ PM.leaves testPfxs

  return (testTaus, m, nTestAddrs)

{-
 - Load the tauTilde estimated directly from a csv file (e.g., produced by MAAD.hs)
 - As a utility for computeT2Test
 -}
tausFromTausFile :: Config -> String -> IO (VU.Vector (Double, Double, Double), Double, Int)
tausFromTausFile conf testfile = do
  contents <- if testfile == "-" then BL8.getContents else BL8.readFile testfile
  let testTaus = contents
        & BL8.lines
        & tail -- assume there will always be a csv header
        & fmap (BL8.split ',') -- :: [[ByteString lazy]]
        & fmap (fmap (read . BL8.unpack))
        & fmap tuplify
        & VU.fromList

  return (testTaus, 9, 0)

  where tuplify [q, tauTilde, sd] = (q, tauTilde, sd)
        tuplify ops = error $ "Unexpected row in taus file: " ++ show ops


{-
 - Load the addresses or structure function in testfile and compare them against the addresses represented by baselinePerPrefixLengths
 - The null hypothesis is that the addresses in testfile have the same distribution as baselinePerPrefixLengths.
 -
 - baselineTaus :: Vector (q, tauTilde, sd)
 -
 - assume q values come in same order as testQs (e.g., increasing)
 -
 - Returns:
 - * the p-value of the test (probability of the observation if the null hypothesis is true)
 - * the raw value of the F-distributed estimator
 - * the number of prefix lengths used (i.e., number of samples)
 - * the number of q values used (i.e., the dimension of the assumed underlying multivariate Normal distribution)
 -}
computeT2Test :: Config -> String -> VU.Vector (Double, Double, Double) -> Int  -> IO CompareResult
computeT2Test conf testfile baselineTaus numAddresses = do

  -- Load the test addresses and compute their tauTilde values, otherwise load structure function directly
  (testTaus, m, nTestAddrs) <- case cfgTestFileIsStructure conf of
    False -> tausFromAddressFile conf testfile
    True -> tausFromTausFile conf testfile

  
  let n :: Double
      n = fromIntegral $ length $ cfgPrefixLengths conf
      -- Define sample size as the number of prefix lengths used

      -- Just look at a fixed set of q-values known to be in the range of convergence
      testQs = [q | q <- qs, q >= 1.0/2.0 && q <= 3.0/2.0 && q /= 1.0]

      -- Size of each sample: each q value is considered a dimension of the sample
      p :: Double
      p = fromIntegral $ length testQs

      xBar :: LA.Vector Double
      xBar = baselineTaus
        & VU.filter (\(q, _, _) -> q `elem` testQs)
        & VU.map (\(_, tau, _) -> tau)
        & VU.toList
        & LA.fromList

      xVar :: LA.Matrix Double
      xVar = baselineTaus
        & VU.filter (\(q, _, _) -> q `elem` testQs)
        & VU.map (\(_, _, sd) -> sd ** 2.0)
        & VU.toList
        & LA.fromList
        & LA.diag -- assume each q is independent

      yBar :: LA.Vector Double
      yBar = testTaus
        & VU.filter (\(q, _, _) -> q `elem` testQs)
        & VU.map (\(_, tau, _) -> tau)
        & VU.toList
        & LA.fromList

      yVar :: LA.Matrix Double
      yVar = testTaus
        & VU.filter (\(q, _, _) -> q `elem` testQs)
        & VU.map (\(_, _, sd) -> sd ** 2.0)
        & VU.toList
        & LA.fromList
        & LA.diag -- assume each q is independent

      -- pooled covariance
      s :: LA.Matrix Double
      s = (1.0 / (n + m - 2)) `LA.scale` (n `LA.scale` xVar + m `LA.scale` yVar)

      delta2 = (((n + m - p - 1) * n * m) / ((n + m - 2) * p * (n + m)))
        * ((yBar - xBar) LA.<# LA.inv s) LA.<.> (yBar - xBar)

  when (n + m - p - 1 <= 0) $
    error $ "Failed to get enough prefix lengths for test with p = " ++ show p

        
  let pValue = 1.0 - cumulative (fDistribution (round p) (round $ n + m - p - 1)) delta2

  return $ CompareResult
    { crPValue = pValue
    , crDelta2 = delta2
    , crN = n
    , crM = m
    , crP = p
    , crNumBaselineAddrs = numAddresses
    , crNumTestAddrs = nTestAddrs
    }


computeT2TestInterpolateSelf :: Config -> VU.Vector (Double, Double, Double) -> Int  -> IO CompareResult
computeT2TestInterpolateSelf conf baselineTaus numAddresses = do
  
  let n :: Double
      n = fromIntegral $ length $ cfgPrefixLengths conf
      m = n
      -- Define sample size as the number of prefix lengths used

      -- Just look at a fixed set of q-values known to be in the range of convergence
      qMin = 1.0 / 2.0
      qMax = 3.0 / 2.0
      testQs = [q | q <- qs, q >= qMin && q <= qMax && q /= 1.0]

      -- Size of each sample: each q value is considered a dimension of the sample
      p :: Double
      p = fromIntegral $ length testQs

      xBar :: LA.Vector Double
      xBar = baselineTaus
        & VU.filter (\(q, _, _) -> q `elem` testQs)
        & VU.map (\(_, tau, _) -> tau)
        & VU.toList
        & LA.fromList

      xVar :: LA.Matrix Double
      xVar = baselineTaus
        & VU.filter (\(q, _, _) -> q `elem` testQs)
        & VU.map (\(_, _, sd) -> sd ** 2.0)
        & VU.toList
        & LA.fromList
        & LA.diag -- assume each q is independent

      -- ys are just interpolated as straight line from first to last of xs
      yBar :: LA.Vector Double
      yBar = testQs
        & fmap (\q -> (LA.minElement xBar) * (1.0 - ((q - qMin) / (qMax - qMin))) + (LA.maxElement xBar) * ((q - qMin) / (qMax - qMin)))
        & LA.fromList

      yVar :: LA.Matrix Double
      yVar = xVar

      -- pooled covariance
      s :: LA.Matrix Double
      s = (1.0 / (n + m - 2)) `LA.scale` (n `LA.scale` xVar + m `LA.scale` yVar)

      delta2 = (((n + m - p - 1) * n * m) / ((n + m - 2) * p * (n + m)))
        * ((yBar - xBar) LA.<# LA.inv s) LA.<.> (yBar - xBar)

  when (n + m - p - 1 <= 0) $
    error $ "Failed to get enough prefix lengths for test with p = " ++ show p

        
  let pValue = 1.0 - cumulative (fDistribution (round p) (round $ n + m - p - 1)) delta2

  return $ CompareResult
    { crPValue = pValue
    , crDelta2 = delta2
    , crN = n
    , crM = m
    , crP = p
    , crNumBaselineAddrs = numAddresses
    , crNumTestAddrs = 0
    }


{-
 - Estimate multinomial CIs
 - TODO: think about if we really need this since we're already doing it pre-filter now?
 -}
multinomialFit :: Config -> (Int, HashMap Prefix Double) -> (Double, Double, Double)
multinomialFit conf (len, pfxs)
  | HM.size pfxs > 0 =
    let n = HM.foldl' (+) 0.0 pfxs
        b = 35.1967321136596 -- Upper tail of the (0.05 / 2^24)-quantile of the Chi distribution with one degree of freedom (Computed in R with: qchisq(p = 0.05 / (2^24), df = 1, lower.tail = FALSE))
        lower_limit = sqrt b / 16
        (maxP, maxB) = HM.elems pfxs
          & fmap (/ n) -- [Double] -- the pi_i's
          & fmap (\pi -> (pi, sqrt (b * pi * (1.0 - pi) / n))) -- [(Double, Double)] -- add the b_i's
          & L.maximumBy (\l r -> compare (snd l) (snd r))
    in (maxP, maxB, lower_limit)
  | otherwise = (0, 0, 0)
  


{-
 - Compute the modified O&W estimator for a single prefix length and q pair
 -
 - Returns the estimated tau(q) and variance
 -}
oneMoment :: Config -> Double -> (HashMap Prefix Double, HashMap Prefix Double) -> (Double, Double)
oneMoment conf q (thisPl, nextPl) =

  -- Note that any normalization cancels out, but we do it anyway because it may help numeric precision (i.e., to avoid sums of super large/small values)
  let total = treeFold (+) 0.0 (HM.elems thisPl)

      thisZ = HM.elems thisPl
        & fmap ((** q) . (/ total))
        & treeFold (+) 0.0

      nextZ = HM.elems nextPl
        & fmap ((** q) . (/ total))
        & treeFold (+) 0.0

      oneD2 (pfx, count) =
        let childSum = PM.children pfx -- [Prefix]
              & fmap (`HM.lookup` nextPl) -- [Maybe Double]
              & filter isJust
              & fmap fromJust -- [Double]
              & (\l -> if length l == 0 then error ("empty child list for prefix " ++ show pfx ++ " with count " ++ show count) else l)
              & fmap ((** q) . (/ total))
              & foldl1 (+)
            mu = count / total
        in (((mu ** q) / thisZ) - (childSum / nextZ)) ** 2.0
              
      d2 = thisPl
        & HM.toList
        & fmap oneD2
        & treeFold (+) 0.0

  in (logBase 2 thisZ - logBase 2 nextZ, d2)

{-
 - Compute multifractal spectrum rows.
 -}
computeSpectrumRows :: VU.Vector (Double, Double, Double)
                    -> (Double, Double)
                    -> [(Double, Double)]
computeSpectrumRows taus (qMax, qMin) =
  -- Estimate alpha and f(alpha) for each q
  let alphas = [1..VU.length taus - 2]
        & fmap (\i ->
                  let (_, prevTau, _) = taus VU.! (i - 1)
                      (q, tau, _) = taus VU.! i
                      (_, nextTau, _) = taus VU.! (i + 1)
                      alpha = (nextTau - prevTau) / (2 * deltaQ)
                      f = q * alpha - tau
                  in (q, (alpha, f))
               )

      -- Filter for alphas derived from qs in critical region and inner range where alpha is monotonically decreasing, assuming any other behavior is just noise
      -- Note this always skips the first alpha. Should be ok if we have enough alpha samples...

      criticalAlphas = alphas
        & filter (\(q, _) -> qMin <= q && q <= qMax)
        & fmap snd
      diffs = (criticalAlphas `zip` drop 1 criticalAlphas)
        & fmap (\((a1, _), (a2, f2)) -> (a1 >= a2, (a2, f2))) -- compute diffs where alpha is strictly decreasing
        & dropWhile (not . fst) -- drop them, assuming it only turns around once at the beginning...
        & takeWhile fst -- ... and once at the end
        & fmap snd 
  in diffs

computeCriticalRegion :: VU.Vector (Double, Double, Double) -> (Double, Double)
computeCriticalRegion taus =
  let alphas = [1..VU.length taus - 2]
        & fmap (\i ->
                  let (_, prevTau, _) = taus VU.! (i - 1)
                      (q, tau, _) = taus VU.! i
                      (_, nextTau, _) = taus VU.! (i + 1)
                      alpha = (nextTau - prevTau) / (2 * deltaQ)
                      f = q * alpha - tau
                  in (q, f)
               )

      qMax = alphas
        & filter ((>= 1) . fst)
        & filter ((> 0) . snd)
        & fmap fst
        & (1.0 :)
        & maximum

      qMin = alphas
        & filter ((<= 0) . fst)
        & filter ((> 0) . snd)
        & fmap fst
        & (0.0 :)
        & minimum

  in (qMax, qMin)

{-
 - Compute generalized dimension rows.
 -}
computeDimensionRows :: Config -> VU.Vector (Double, Double, Double) -> PrefixMap Double -> [(Double, Double, Double)]
computeDimensionRows conf taus pfxs =
  let getDim q = taus
        & VU.find (\(q', _, _) -> q' == q)
        & maybe (error $ "Failed to find expected q value q = " ++ show q) (\(q, tauTilde, sd) -> (tauTilde / (q - 1.0), sd))

      (d0, sd0) = getDim 0.0
      d1 = infoDim conf pfxs
      (d2, sd2) = getDim 2.0
        
  in [(0.0, d0, sd0), (1.0, d1, 0.0), (2.0, d2, sd2)]

{-
 - Compute D_1, the information dimension
 -}
infoDim :: Config -> PrefixMap Double -> Double
infoDim conf pfxs =
  -- lim_{r to 0} ( sum_i p_i * log(p_i) ) / log(r)
  -- lim_{l to infty} (sum_i p_i * log(p_i)) / -l
  let total = treeFold (+) 0.0 $ fmap snd $ PM.leaves pfxs
      oneEntropy :: Int -> Double
      oneEntropy pl = pfxs
        & PM.sliceAtLength pl
        & PM.leaves
        & fmap (\(_, weight) ->
                  let p = weight / total in p * logBase 2 p
               )
        & treeFold (+) 0.0
      entropies = cfgPrefixLengths conf
        & fmap oneEntropy
        & VU.fromList
      pls = VU.generate (VU.length entropies) (negate . fromIntegral)
      (coef, _r2) = Reg.olsRegress [pls] entropies
  in coef VU.! 0

computePartitions :: Config -> PrefixMap Double -> [(Double, [(Double, Double)])]
computePartitions conf pfxs =
  let total = treeFold (+) 0.0 $ fmap snd $ PM.leaves pfxs
      maxPl = case PM.prefixMapVersion pfxs of
        Addr4 _ -> 32
        Addr6 _ -> 128

      getZ q pl =
        let z = pfxs
              & PM.sliceAtLength pl
              & PM.leaves
              & fmap ((** q) . (/ total) . snd)
              & treeFold (+) 0.0
        in (fromIntegral pl, z)
        
      oneQ q =
        let zs = fmap (getZ q) [0..maxPl]
        in (q, zs)

  in fmap oneQ [-2.0, -2.0 + 1.0/4.0..4.0]

{-
 - Report the singularity estimates of each address w.r.t. the prefix map
 - Returns (alpha, (address, intercept, r2, number of prefix-lengths actually used))
 -}
computeSingularities :: Config -> PrefixMap Double -> [(Double, (Addr, Double, Double, Int))]
computeSingularities conf pfxs =
  let addrs = PM.leaves pfxs
      maxPl = case PM.prefixMapVersion pfxs of
        Addr4 _ -> 32
        Addr6 _ -> 128

      total = treeFold (+) 0.0 $ fmap snd addrs

      getSingularity :: (Prefix, Double) -> (Double, (Addr, Double, Double, Int))
      getSingularity (Prefix addr pl, _)
        | pl == maxPl =
            let oneLevel l =
                  let pfx = PM.preserve_upper_bits (Prefix addr pl) l
                      mu = fromJust $ PM.lookup pfx pfxs
                      muNorm = mu  / total
                  in (- logBase 2 muNorm, mu /= 1)
  
                muLogs = VU.generate (maxPl + 1) oneLevel & VU.takeWhile snd & VU.map fst
                pls = VU.generate (VU.length muLogs) fromIntegral

                (coef, r2) = Reg.olsRegress [pls] muLogs
            in (coef VU.! 0, (addr, coef VU.! 1, r2, VU.length muLogs))
        | otherwise =
            error $ "Got a /" ++ show pl ++ " prefix as a leaf in computeSingularities. Something's broken."

  in addrs
     & fmap getSingularity
     & L.sortOn fst

{-
 - Emit results in the requested output format.
 - Just dispatch based on csv or json.
 -}
emitResults :: Config
            -> Metadata
            -> Results
            -> IO ()
emitResults conf =
  case cfgFormat conf of
    OutputCsv -> emitCsvResults conf
    OutputJson -> emitJsonResults conf

{-
 - Emit csv results to stdout or files.
 -}
emitCsvResults :: Config
               -> Metadata
               -> Results
               -> IO ()
emitCsvResults conf metadata res =
  if cfgOutPrefix conf == "-"
  then do
    maybe (return ()) (writeStructureCsv stdout) (resStructure res)
    maybe (return ()) (writeSpectrumCsv stdout) (resSpectrum res)
    maybe (return ()) (writeDimensionsCsv stdout) (resDimensions res)
    maybe (return ()) (writePartitionsCsv stdout) (resPartitions res)
    maybe (return ()) (writeSingularities stdout) (resSingularities res)
    maybe (return ()) (writeWeights stdout) (resWeights res)
    maybe (return ()) (writeT2TestResult stdout) (resTest res)
    maybe (return ()) (writeT2TestResult stdout) (resCompare res)
  else do
    writeMetadata conf metadata
    maybe (return ()) (writeStructureFile conf) (resStructure res)
    maybe (return ()) (writeSpectrumFile conf) (resSpectrum res)
    maybe (return ()) (writeDimensionsFile conf) (resDimensions res)
    maybe (return ()) (writePartitionsFile conf) (resPartitions res)
    maybe (return ()) (writeSingularitiesFile conf) (resSingularities res)
    maybe (return ()) (writeWeightsFile conf) (resWeights res)
    maybe (return ()) (writeT2TestResultSelfFile conf) (resTest res)
    maybe (return ()) (writeT2TestResultFile conf) (resCompare res)

{-
 - Write some metadata to keep track of config and parameters that were auto-generated here
 -}
writeMetadata :: Config -> Metadata -> IO ()
writeMetadata conf metadata = do
  let outfile = cfgOutPrefix conf ++ "_metadata.csv"
  hPutStrLn stderr $ "Writing metadata to " ++ outfile
  withFile outfile WriteMode $ \hdl -> do
    hPutStrLn hdl "key,value"
    hPutStrLn hdl $ "input," ++ metaInput metadata
    hPutStrLn hdl $ "min_prefix_length," ++ show (metaMinPrefixLength metadata)
    hPutStrLn hdl $ "max_prefix_length," ++ show (metaMaxPrefixLength metadata)
    hPutStrLn hdl $ "total_addrs," ++ show (metaTotalAddrs metadata)
    hPutStrLn hdl $ "did_auto_stop," ++ case (metaDidAutoStop metadata) of
      Just max_pl -> "True"
      Nothing -> "False"
    forM_ (metaPreFilterPrefixCounts metadata) $ \(pl, count) ->
      hPutStrLn hdl $ "pre_filter_prefix_count/" ++ show pl ++ "," ++ show count
    forM_ (metaPrefixCounts metadata) $ \(pl, count) ->
      hPutStrLn hdl $ "prefix_count/" ++ show pl ++ "," ++ show count
    forM_ (metaMultinomialFits metadata `zip` metaPrefixCounts metadata) $ \((maxP, maxB, lower_limit), (pl, _)) ->
      hPutStrLn hdl $ "multinomial_fit/" ++ show pl ++ "," ++ show maxP ++ ":" ++ show maxB ++ ":" ++ show lower_limit
    forM_ (metaPerPrefixLengthVars metadata) $ \(pl, q, tau, v) ->
      hPutStrLn hdl $ "var/" ++ show pl ++ "," ++ show q ++ ":" ++ show tau ++ ":" ++ show v
    hPutStrLn hdl $ "q_max," ++ show (fst $ metaCriticalRegion metadata)
    hPutStrLn hdl $ "q_min," ++ show (snd $ metaCriticalRegion metadata)

{-
 - Write the structure function
 -}
writeStructureFile :: Config -> [(Double, Double, Double)] -> IO ()
writeStructureFile conf rows = do
  let outfile = cfgOutPrefix conf ++ "_structure.csv"
  hPutStrLn stderr $ "Writing structure function to " ++ outfile
  withFile outfile WriteMode (\hdl -> writeStructureCsv hdl rows)

writeStructureCsv :: Handle -> [(Double, Double, Double)] -> IO ()
writeStructureCsv hdl rows = do
  hPutStrLn hdl "q,tauTilde,sd"
  forM_ rows $ \(q, tauTilde, sd) ->
    hPutStrLn hdl (show q ++ "," ++ show tauTilde ++ "," ++ show sd)


{-
 - Write multifractal spectrum.
 -}
writeSpectrumFile :: Config -> [(Double, Double)] -> IO ()
writeSpectrumFile conf rows = do
  let outfile = cfgOutPrefix conf ++ "_spectrum.csv"
  hPutStrLn stderr $ "Writing multifractal spectrum to " ++ outfile
  withFile outfile WriteMode (\hdl -> writeSpectrumCsv hdl rows)

writeSpectrumCsv :: Handle -> [(Double, Double)] -> IO ()
writeSpectrumCsv hdl rows = do
  hPutStrLn hdl "alpha,f"
  forM_ rows $ \(alpha, f) ->
    hPutStrLn hdl (show alpha ++ "," ++ show f)


{-
 - Write generalized dimensions.
 -}
writeDimensionsFile :: Config -> [(Double, Double, Double)] -> IO ()
writeDimensionsFile conf rows = do
  let outfile = cfgOutPrefix conf ++ "_dimensions.csv"
  hPutStrLn stderr $ "Writing generalized dimensions to " ++ outfile
  withFile outfile WriteMode (\hdl -> writeDimensionsCsv hdl rows)

writeDimensionsCsv :: Handle -> [(Double, Double, Double)] -> IO ()
writeDimensionsCsv hdl rows = do
  hPutStrLn hdl "q,dim,sd"
  forM_ rows $ \(q, dim, sd) ->
    hPutStrLn hdl (show q ++ "," ++ show dim ++ "," ++ show sd)

{-
 - Write partition functions.
 -}
writePartitionsFile :: Config -> [(Double, [(Double, Double)])] -> IO ()
writePartitionsFile conf rows = do
  let outfile = cfgOutPrefix conf ++ "_partitions.csv"
  hPutStrLn stderr $ "Writing partition functions to " ++ outfile
  withFile outfile WriteMode (\hdl -> writePartitionsCsv hdl rows)

writePartitionsCsv :: Handle -> [(Double, [(Double, Double)])] -> IO ()
writePartitionsCsv hdl rows = do
  hPutStrLn hdl "q,pl,z"
  forM_ rows $ \(q, zs) ->
    forM_ zs $ \(pl, z) ->
                 hPutStrLn hdl (show q ++ "," ++ show pl ++ "," ++ show z)

{-
 - Write singularities
 -}
writeSingularitiesFile :: Config -> [(Double, (Addr, Double, Double, Int))] -> IO ()
writeSingularitiesFile conf rows = do
  let outfile = cfgOutPrefix conf ++ "_singularities.csv"
  hPutStrLn stderr $ "Writing singularities to " ++ outfile
  withFile outfile WriteMode (\hdl -> writeSingularities hdl rows)

writeSingularities :: Handle -> [(Double, (Addr, Double, Double, Int))] -> IO ()
writeSingularities hdl rows = do
  hPutStrLn hdl "alpha,addr,intercept,r2,num_levels"
  forM_ rows $ \(alpha, (addr, intercept, r2, num_levels)) -> do
    hPutStrLn hdl $ show alpha
      ++ "," ++ show addr
      ++ "," ++ show intercept
      ++ "," ++ show r2
      ++ "," ++ show num_levels

{-
 - Write singularities
 -}
writeWeightsFile :: Config -> [(Int, Addr, Double, Double, Double)] -> IO ()
writeWeightsFile conf rows = do
  let outfile = cfgOutPrefix conf ++ "_weights.csv"
  hPutStrLn stderr $ "Writing weightsto " ++ outfile
  withFile outfile WriteMode (\hdl -> writeWeights hdl rows)

writeWeights :: Handle -> [(Int, Addr, Double, Double, Double)] -> IO ()
writeWeights hdl rows = do
  hPutStrLn hdl "pl,addr,mu,left,right"
  forM_ rows $ \(pl, addr, mu, left, right) -> do
    hPutStrLn hdl $ show pl
      ++ "," ++ show addr
      ++ "," ++ show mu
      ++ "," ++ show left
      ++ "," ++ show right


{-
 - Write t2-test based on interpolated structure function
 -}

writeT2TestResultSelfFile :: Config -> CompareResult -> IO ()
writeT2TestResultSelfFile conf res = do
  let outfile = cfgOutPrefix conf ++ "_test.csv"
  hPutStrLn stderr $ "Writing test results to " ++ outfile
  withFile outfile WriteMode (\hdl -> writeT2TestResult hdl res)

{-
 - Write t2-test comparison results
 -}
writeT2TestResultFile :: Config -> CompareResult -> IO ()
writeT2TestResultFile conf res = do
  let outfile = cfgOutPrefix conf ++ "_compare.csv"
  hPutStrLn stderr $ "Writing test results to " ++ outfile
  withFile outfile WriteMode (\hdl -> writeT2TestResult hdl res)

writeT2TestResult :: Handle -> CompareResult -> IO ()
writeT2TestResult hdl res = do
  hPutStrLn hdl "p_value,delta2,n,m,p,numBaselineAddrs,numTestAddrs"
  hPutStrLn hdl $ show (crPValue res)
    ++ "," ++ show (crDelta2 res)
    ++ "," ++ show (crN res)
    ++ "," ++ show (crM res)
    ++ "," ++ show (crP res)
    ++ "," ++ show (crNumBaselineAddrs res)
    ++ "," ++ show (crNumTestAddrs res)

{-
 - Emit json results to stdout or file.
 -}
emitJsonResults :: Config
                -> Metadata
                -> Results
                -> IO ()
emitJsonResults conf metadata res = do
  let payload = encodeResultsJson metadata res
  if cfgOutPrefix conf == "-"
  then BL8.putStrLn payload
  else do
    let outfile = cfgOutPrefix conf ++ ".json"
    hPutStrLn stderr $ "Writing json results to " ++ outfile
    BL8.writeFile outfile (payload <> "\n")

encodeResultsJson :: Metadata
                  -> Results
                  -> BL8.ByteString
encodeResultsJson metadata res =
  encode $
    object $
      [ "schemaVersion" .= (1 :: Int)
      , "metadata" .= encodeMetadataJson metadata
      ]
      ++ maybe [] (\rows -> ["structure" .= encodeStructureRowsJson rows]) (resStructure res)
      ++ maybe [] (\rows -> ["spectrum" .= encodeSpectrumRowsJson rows]) (resSpectrum res)
      ++ maybe [] (\rows -> ["dimensions" .= encodeDimensionRowsJson rows]) (resDimensions res)
      ++ maybe [] (\rows -> ["partitions" .= encodePartitionsRowsJson rows]) (resPartitions res)
      ++ maybe [] (\rows -> ["singularities" .= encodeSingularitiesRowsJson rows]) (resSingularities res)
      -- TODO: add testResult: both t-test and t2-test/compare !!

encodeMetadataJson :: Metadata -> Value
encodeMetadataJson metadata =
  object
    [ "input" .= metaInput metadata
    , "minPrefixLength" .= metaMinPrefixLength metadata
    , "maxPrefixLength" .= metaMaxPrefixLength metadata
    , "totalAddrs" .= metaTotalAddrs metadata
    , "didAutoStop" .= metaDidAutoStop metadata
    , "prefix_counts" .= encodePrefixCountsJson (metaPrefixCounts metadata)
    , "pre_filter_prefix_counts" .= encodePrefixCountsJson (metaPreFilterPrefixCounts metadata)
    , "multinomial_fits" .= encodeMultinomialFits (fmap fst (metaPrefixCounts metadata) `zip` metaMultinomialFits metadata)
    , "per_prefix_length_vars" .= encodePerPrefixLengthVarsJson (metaPerPrefixLengthVars metadata)
    , "qMax" .= fst (metaCriticalRegion metadata)
    , "qMin" .= snd (metaCriticalRegion metadata)
    ]

encodePrefixCountsJson :: [(Int, Int)] -> [Value]
encodePrefixCountsJson counts =
  fmap
    (\(pl, count) ->
       object
         [ "pl" .= pl
         , "count" .= count
         ]
    )
    counts

encodeMultinomialFits :: [(Int, (Double, Double, Double))] -> [Value]
encodeMultinomialFits fits =
  fmap
    (\(pl, (maxP, maxB, lower_limit)) ->
       object
         [ "pl" .= pl
         , "maxP" .= maxP
         , "maxB" .= maxB
         , "lower_limit" .= lower_limit
         ]
    )
    fits

encodePerPrefixLengthVarsJson :: [(Int, Double, Double, Double)] -> [Value]
encodePerPrefixLengthVarsJson vars =
  fmap
    (\(pl, q, tau, v) ->
       object
         [ "pl" .= pl
         , "q" .= q
         , "tau" .= tau
         , "var" .= v
         ]
    )
    vars

encodeStructureRowsJson :: [(Double, Double, Double)] -> [Value]
encodeStructureRowsJson rows =
  fmap
    (\(q, tauTilde, sd) ->
      object
        [ "q" .= q
        , "tauTilde" .= tauTilde
        , "sd" .= sd
        ]
    )
    rows

encodeSpectrumRowsJson :: [(Double, Double)] -> [Value]
encodeSpectrumRowsJson rows =
  fmap
    (\(alpha, f) ->
      object
        [ "alpha" .= alpha
        , "f" .= f
        ]
    )
    rows

encodeDimensionRowsJson :: [(Double, Double, Double)] -> [Value]
encodeDimensionRowsJson rows =
  fmap
    (\(q, dim, sd) ->
      object
        [ "q" .= q
        , "dim" .= dim
        , "sd" .= sd
        ]
    )
    rows

encodePartitionsRowsJson :: [(Double, [(Double, Double)])] -> [Value]
encodePartitionsRowsJson =
  concatMap
    (\(q, zs) ->
       fmap (\(pl, z) ->
               object
               [ "q" .= q
               , "pl" .= pl
               , "z" .= z
               ]
            ) zs
    )

encodeSingularitiesRowsJson :: [(Double, (Addr, Double, Double, Int))] -> [Value]
encodeSingularitiesRowsJson =
  fmap
    (\(alpha, (addr, intercept, r2, num_levels)) ->
        object
        [ "alpha" .= alpha
        , "addr" .= show addr
        , "intercept" .= intercept
        , "r2" .= r2
        , "num_levels" .= num_levels
        ]
    )


