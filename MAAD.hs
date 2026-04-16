{-
 - Copyright: 2026 Chris Misa
 - License: (See ./LICENSE)
 -
 - Entry point for running various multifractal analysis of IP address space data.
 -
 -}

module MAAD where

import System.Environment
import System.IO
import Data.Function ((&))
import Control.Arrow
import Control.Monad

import Data.Word
import Data.Maybe

import qualified Data.ByteString.Char8 as B
import Data.ByteString.Char8 (ByteString)

import qualified Data.List as L

import Options.Applicative -- optparse-applicative

import qualified Data.Vector.Unboxed as VU
import qualified Statistics.Sample as SS
import qualified Statistics.Regression as Reg

import Data.TreeFold (treeFold)

-- Local imports
import Common
import PrefixMap (Prefix(..), PrefixMap)
import qualified PrefixMap as PM

defaultSpilloverThreshold :: Double
defaultSpilloverThreshold = 0.05

deltaQ :: Double
deltaQ = 1.0 / 8.0

-- Min q based on theoretic range of normalicy of tauTilde(q)
minQ :: Double
minQ = -1.0 / 2.0

-- Max q based on theoretic range of convergence of tauTilde(q) because it's less sensitive in the Legendre transform
maxQ :: Double
maxQ = 3.5

qs :: [Double]
qs = [minQ, minQ+deltaQ..maxQ]

data Config = Config
  { cfgFilepath :: String
  , cfgOutPrefix :: String
  , cfgStructure :: Bool
  , cfgSpectrum :: Bool
  , cfgDimensions :: Bool
  , cfgCsv :: Bool
  , cfgAddrCol :: Maybe Int
  , cfgMeasureCol :: Maybe Int
  , cfgSkipFirst :: Bool
  , cfgSpilloverThresh :: Double
  , cfgPrefixLengths :: [Int]
  }
  deriving (Show)

optparser :: Parser Config
optparser = Config
  <$> strOption ( long "input"
                  <> metavar "FILEPATH"
                  <> help "File to read (csv or one address on each line)."
                )
  <*> strOption ( long "output"
                  <> metavar "FILEPATH_PREFIX"
                  <> help "Prefix for output files."
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
  <*> option auto ( long "spillover-threshold" <> metavar "DELTA"
                    <> value defaultSpilloverThreshold <> showDefault
                    <> help "Threshold for determining when a prefix is estimated to have spilled over. Mostly only important for determining max prefix length."
                  )
  <*> pure []

opts :: ParserInfo Config
opts = info (optparser <**> helper)
  ( fullDesc
    <> progDesc "Compute a combination of different multifractal analyses of a given set of IP addresses, optimally based on a per-address measure."
    <> header "MAAD - Multifractal Address-space Anomaly Detection"
  )

main :: IO ()
main = do
  conf <- execParser opts
  if not (cfgStructure conf) && not (cfgSpectrum conf) && not (cfgDimensions conf)
    then putStrLn "Must specify one of --structure, --spectrum, or --dimensions to compute."
    else if (isJust (cfgAddrCol conf) || isJust (cfgMeasureCol conf)) && not (cfgCsv conf)
    then putStrLn "To specify --addr-col or --meas-col, you must also indicate the input is a csv file by specifying --csv"
    else run conf

{-
 - Run analysis and write results as described by the given configuration.
 -}
run :: Config -> IO ()
run conf = do

  -- Load in the addresses and optional associated "weights"
  pfxs <-
        if cfgCsv conf
        then let extract_addr = flip (!!) (fromMaybe 0 (cfgAddrCol conf)) -- default to column 0
                 extract_meas =
                   case cfgMeasureCol conf of
                     Just col -> read . B.unpack . flip (!!) col
                     Nothing -> const 1.0 -- default to constant 1.0 for each address
             in PM.fromFile (cfgFilepath conf) (cfgSkipFirst conf) extract_addr extract_meas
        else PM.fromFile (cfgFilepath conf) (cfgSkipFirst conf) head (const 1.0)

  let !firstAtomicLength = PM.firstAtomicLength pfxs
  let !firstSpilloverLength = PM.firstSpilloverLength (cfgSpilloverThresh conf) pfxs

  putStrLn $ "First atomic length: " ++ show firstAtomicLength
  putStrLn $ "First spill-over length: " ++ show firstSpilloverLength
  let conf' = conf { cfgPrefixLengths = [firstAtomicLength .. firstSpilloverLength] }

  -- Compute the structure function
  let oneTau q = 
        let moms = fmap (oneMoment pfxs q) (cfgPrefixLengths conf')
            n = fromIntegral (length moms)
            tauTilde = moms
              & fmap fst
              & VU.fromList
              & SS.mean
            sd = moms
              & fmap snd
              & treeFold (+) 0.0
              & ((/ n) . sqrt)
        in (q, tauTilde, sd)

      taus = qs & VU.fromList & VU.map oneTau

  -- Write metadata
  writeMetadata conf' pfxs
  
  -- Write the structure function if requested
  when (cfgStructure conf') (runStructure conf' taus)

  -- Compute and write the multifractal spectrum if requested
  when (cfgSpectrum conf') (runSpectrum conf' taus)

  -- Compute and write the generalized dimensions if requested
  when (cfgDimensions conf') (runDimensions conf' taus pfxs)

{-
 - Write some metadata to keep track of config and parameters that were auto-generated here
 -}
writeMetadata :: Config -> PrefixMap Double -> IO ()
writeMetadata conf pfxs = do
  let outfile = cfgOutPrefix conf ++ "_metadata.csv"
  putStrLn $ "Writing metadata to " ++ outfile
  withFile outfile WriteMode $ \hdl -> do
    hPutStrLn hdl "key,value"
    hPutStrLn hdl $ "input," ++ cfgFilepath conf
    hPutStrLn hdl $ "min_prefix_length," ++ show (foldl1 min (cfgPrefixLengths conf))
    hPutStrLn hdl $ "max_prefix_length," ++ show (foldl1 max (cfgPrefixLengths conf))
    hPutStrLn hdl $ "total_addrs," ++ show (length (PM.leaves pfxs))

{-
 - Write the structure function
 -}
runStructure :: Config -> VU.Vector (Double, Double, Double) -> IO ()
runStructure conf taus = do
  let outfile = cfgOutPrefix conf ++ "_structure.csv"
  putStrLn $ "Writing structure function to " ++ outfile
  withFile outfile WriteMode $ \hdl -> do
    hPutStrLn hdl "q,tauTilde,sd"
    VU.forM_ taus $ \(q, tauTilde, sd) -> hPutStrLn hdl (show q ++ "," ++ show tauTilde ++ "," ++ show sd)

{-
 - Compute and write multifractal spectrum
 -}
runSpectrum :: Config -> VU.Vector (Double, Double, Double) -> IO ()
runSpectrum conf taus = do
  -- Estimate alpha and f(alpha) for each q
  let alphas = [1..VU.length taus - 2]
        & fmap (\i ->
                  let (_, prevTau, _) = taus VU.! (i - 1)
                      (q, tau, _) = taus VU.! i
                      (_, nextTau, _) = taus VU.! (i + 1)
                      alpha = (nextTau - prevTau) / (2 * deltaQ)
                      f = q * alpha - tau
                  in (alpha, f)
               )

      -- Filter for range where alpha is monotonic decreasing
      -- Note this always skips the first alpha. Should be ok if we have enough alpha samples...
      diffs = zip alphas (tail alphas)
        & fmap (\((a1, _), (a2, f2)) -> (a1 > a2, (a2, f2)))
        & dropWhile (not . fst) -- assume it only turns around once at beginning and once at end...
        & takeWhile fst
        & fmap snd

  -- Write to file
  let outfile = cfgOutPrefix conf ++ "_spectrum.csv"
  putStrLn $ "Writing multifractal spectrum to " ++ outfile
  withFile outfile WriteMode $ \hdl -> do
    hPutStrLn hdl "alpha,f"
    forM_ diffs $ \(alpha, f) -> do
      hPutStrLn hdl (show alpha ++ "," ++ show f)

{-
 - Compute and write generalized dimensions
 -}
runDimensions :: Config -> VU.Vector (Double, Double, Double) -> PrefixMap Double -> IO ()
runDimensions conf taus pfxs = do
  let d1 = infoDim conf pfxs

  -- Write to file
  let outfile = cfgOutPrefix conf ++ "_dimensions.csv"
  putStrLn $ "Writing generalized dimensions to " ++ outfile
  withFile outfile WriteMode $ \hdl -> do
    hPutStrLn hdl "q,dim"
    hPutStrLn hdl ("1.0," ++ show d1)
    taus
      & VU.filter (\(q, _, _) -> q == 0.0 || q == 2.0)
      & VU.mapM_ (\(q, tauTilde, sd) -> do
                     let dq = tauTilde / (q - 1.0)
                     hPutStrLn hdl (show q ++ "," ++ show dq)
                 )

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


{-
 - Compute the modified O&W estimator for a single prefix length and q pair
 -
 - Returns the estimated tau(q) and variance
 -}
oneMoment :: PrefixMap Double -> Double -> Int -> (Double, Double)
oneMoment pm q pl =
  let thisPl = pm
        & PM.sliceAtLength pl
        & PM.filter (\_ count -> count > 1) -- TODO: generalize the notion of singularity!!!

      nextPl = pm
        & PM.sliceAtLength (pl + 1)
        & PM.filter (\pfx _ -> PM.prefixLength pfx <= pl || PM.lookupDefault 0 thisPl (PM.preserve_upper_bits32 pfx pl) > 0)

      -- Note that any normalization cancels out, but we do it anyway because it may help numeric precision (i.e., to avoid sums of super large/small values)
      total = treeFold (+) 0.0 $ fmap snd $ PM.leaves thisPl

      nextZ = nextPl
        & PM.leaves
        & fmap ((** q) . (/ total) . snd)
        & treeFold (+) 0.0

      thisZ = thisPl
        & PM.leaves
        & fmap ((** q) . (/ total) . snd)
        & treeFold (+) 0.0

      oneD2 (pfx, count) =
        let childSum = PM.children pfx
              & fmap (PM.lookupDefault 0 nextPl)
              & filter (> 0)
              & (\l -> if length l == 0 then error ("empty child list for prefix " ++ show pfx ++ " with count " ++ show count) else l)
              & fmap ((** q) . (/ total))
              & foldl1 (+)
            mu = count / total
        in (((mu ** q) / thisZ) - (childSum / nextZ)) ** 2.0
              
      d2 = thisPl
        & PM.leaves
        & filter (\(pfx, _) -> PM.prefixLength pfx == pl)
        & fmap oneD2
        & treeFold (+) 0.0

  in (logBase 2 thisZ - logBase 2 nextZ, d2)
