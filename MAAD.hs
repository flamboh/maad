{-# LANGUAGE BangPatterns #-}

{-
 - Copyright: 2026 Chris Misa
 - License: (See ./LICENSE)
 -
 - Entry point for running various multifractal analysis of IP address space data.
 -
 -}

module MAAD where

import System.Environment
import System.Exit
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

data OutputFormat = OutputCsv | OutputJson
  deriving (Eq, Show)

data Config = Config
  { cfgFilepath :: String
  , cfgOutPrefix :: String
  , cfgFormat :: OutputFormat
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

data Metadata = Metadata
  { metaInput :: String
  , metaMinPrefixLength :: Int
  , metaMaxPrefixLength :: Int
  , metaTotalAddrs :: Int
  }

optparser :: Parser Config
optparser = Config
  <$> strOption ( long "input"
                  <> metavar "FILEPATH"
                  <> help "File to read (csv or one address on each line)."
                )
  <*> strOption ( long "output"
                  <> metavar "FILEPATH_PREFIX"
                  <> help "Prefix for output files, or - for stdout."
                )
  <*> option (eitherReader parseOutputFormat)
        ( long "format"
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
    then dieWith "Must specify one of --structure, --spectrum, or --dimensions to compute."
    else if (isJust (cfgAddrCol conf) || isJust (cfgMeasureCol conf)) && not (cfgCsv conf)
    then dieWith "To specify --addr-col or --meas-col, you must also indicate the input is a csv file by specifying --csv"
    else if cfgOutPrefix conf == "-" && cfgFormat conf == OutputCsv && requestedAnalysisCount conf > 1
    then dieWith "CSV stdout only supports a single requested analysis; use --format json or a file prefix."
    else run conf

parseOutputFormat :: String -> Either String OutputFormat
parseOutputFormat "csv" = Right OutputCsv
parseOutputFormat "json" = Right OutputJson
parseOutputFormat _ = Left "FORMAT must be one of: csv, json"

formatName :: OutputFormat -> String
formatName OutputCsv = "csv"
formatName OutputJson = "json"

dieWith :: String -> IO ()
dieWith msg = hPutStrLn stderr msg >> exitFailure

requestedAnalysisCount :: Config -> Int
requestedAnalysisCount conf =
  length $
    filter id
      [ cfgStructure conf
      , cfgSpectrum conf
      , cfgDimensions conf
      ]

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
        else PM.fromFile (cfgFilepath conf) (cfgSkipFirst conf) extractSingleAddr (const 1.0)

  let !firstAtomicLength = PM.firstAtomicLength pfxs
  let !firstSpilloverLength = PM.firstSpilloverLength (cfgSpilloverThresh conf) pfxs

  hPutStrLn stderr $ "First atomic length: " ++ show firstAtomicLength
  hPutStrLn stderr $ "First spill-over length: " ++ show firstSpilloverLength
  let conf' = conf { cfgPrefixLengths = [firstAtomicLength .. firstSpilloverLength] }
      metadata = Metadata
        { metaInput = cfgFilepath conf
        , metaMinPrefixLength = foldl1 min (cfgPrefixLengths conf')
        , metaMaxPrefixLength = foldl1 max (cfgPrefixLengths conf')
        , metaTotalAddrs = length (PM.leaves pfxs)
        }

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

      structureRows = if cfgStructure conf' then Just (VU.toList taus) else Nothing
      spectrumRows = if cfgSpectrum conf' then Just (computeSpectrumRows taus) else Nothing
      dimensionRows = if cfgDimensions conf' then Just (computeDimensionRows conf' taus pfxs) else Nothing

  emitResults conf' metadata structureRows spectrumRows dimensionRows

{-
 - Emit results in the requested output format.
 -}
emitResults :: Config -> Metadata -> Maybe [(Double, Double, Double)] -> Maybe [(Double, Double)] -> Maybe [(Double, Double)] -> IO ()
emitResults conf metadata structureRows spectrumRows dimensionRows =
  case cfgFormat conf of
    OutputCsv -> emitCsvResults conf metadata structureRows spectrumRows dimensionRows
    OutputJson -> emitJsonResults conf metadata structureRows spectrumRows dimensionRows

{-
 - Write metadata to csv file.
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

{-
 - Emit csv results to stdout or files.
 -}
emitCsvResults :: Config -> Metadata -> Maybe [(Double, Double, Double)] -> Maybe [(Double, Double)] -> Maybe [(Double, Double)] -> IO ()
emitCsvResults conf metadata structureRows spectrumRows dimensionRows =
  if cfgOutPrefix conf == "-"
  then
    case () of
      _ | cfgStructure conf -> maybe (return ()) (writeStructureCsv stdout) structureRows
        | cfgSpectrum conf -> maybe (return ()) (writeSpectrumCsv stdout) spectrumRows
        | otherwise -> maybe (return ()) (writeDimensionsCsv stdout) dimensionRows
  else do
    writeMetadata conf metadata
    maybe (return ()) (writeStructureFile conf) structureRows
    maybe (return ()) (writeSpectrumFile conf) spectrumRows
    maybe (return ()) (writeDimensionsFile conf) dimensionRows

{-
 - Write structure rows to csv file.
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
 - Compute multifractal spectrum rows.
 -}
computeSpectrumRows :: VU.Vector (Double, Double, Double) -> [(Double, Double)]
computeSpectrumRows taus =
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
      diffs = zip alphas (drop 1 alphas)
        & fmap (\((a1, _), (a2, f2)) -> (a1 > a2, (a2, f2)))
        & dropWhile (not . fst) -- assume it only turns around once at beginning and once at end...
        & takeWhile fst
        & fmap snd
  in diffs

{-
 - Write spectrum rows to csv file.
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
 - Compute generalized dimension rows.
 -}
computeDimensionRows :: Config -> VU.Vector (Double, Double, Double) -> PrefixMap Double -> [(Double, Double)]
computeDimensionRows conf taus pfxs =
  let d1 = infoDim conf pfxs
      otherDims = taus
        & VU.toList
        & filter (\(q, _, _) -> q == 0.0 || q == 2.0)
        & fmap (\(q, tauTilde, _) -> (q, tauTilde / (q - 1.0)))
  in (1.0, d1) : otherDims

{-
 - Write dimension rows to csv file.
 -}
writeDimensionsFile :: Config -> [(Double, Double)] -> IO ()
writeDimensionsFile conf rows = do
  let outfile = cfgOutPrefix conf ++ "_dimensions.csv"
  hPutStrLn stderr $ "Writing generalized dimensions to " ++ outfile
  withFile outfile WriteMode (\hdl -> writeDimensionsCsv hdl rows)

writeDimensionsCsv :: Handle -> [(Double, Double)] -> IO ()
writeDimensionsCsv hdl rows = do
  hPutStrLn hdl "q,dim"
  forM_ rows $ \(q, dim) ->
    hPutStrLn hdl (show q ++ "," ++ show dim)

{-
 - Emit json results to stdout or file.
 -}
emitJsonResults :: Config -> Metadata -> Maybe [(Double, Double, Double)] -> Maybe [(Double, Double)] -> Maybe [(Double, Double)] -> IO ()
emitJsonResults conf metadata structureRows spectrumRows dimensionRows = do
  let payload = encodeResultsJson metadata structureRows spectrumRows dimensionRows
  if cfgOutPrefix conf == "-"
  then putStrLn payload
  else do
    let outfile = cfgOutPrefix conf ++ ".json"
    hPutStrLn stderr $ "Writing json results to " ++ outfile
    writeFile outfile (payload ++ "\n")

encodeResultsJson :: Metadata -> Maybe [(Double, Double, Double)] -> Maybe [(Double, Double)] -> Maybe [(Double, Double)] -> String
encodeResultsJson metadata structureRows spectrumRows dimensionRows =
  jsonObject $
    [ ("schemaVersion", "1")
    , ("metadata", encodeMetadataJson metadata)
    ]
    ++ maybe [] (\rows -> [("structure", encodeStructureRowsJson rows)]) structureRows
    ++ maybe [] (\rows -> [("spectrum", encodeSpectrumRowsJson rows)]) spectrumRows
    ++ maybe [] (\rows -> [("dimensions", encodeDimensionRowsJson rows)]) dimensionRows

encodeMetadataJson :: Metadata -> String
encodeMetadataJson metadata =
  jsonObject
    [ ("input", jsonString (metaInput metadata))
    , ("minPrefixLength", show (metaMinPrefixLength metadata))
    , ("maxPrefixLength", show (metaMaxPrefixLength metadata))
    , ("totalAddrs", show (metaTotalAddrs metadata))
    ]

encodeStructureRowsJson :: [(Double, Double, Double)] -> String
encodeStructureRowsJson rows =
  jsonArray $
    fmap (\(q, tauTilde, sd) ->
            jsonObject
              [ ("q", show q)
              , ("tauTilde", show tauTilde)
              , ("sd", show sd)
              ]
         ) rows

encodeSpectrumRowsJson :: [(Double, Double)] -> String
encodeSpectrumRowsJson rows =
  jsonArray $
    fmap (\(alpha, f) ->
            jsonObject
              [ ("alpha", show alpha)
              , ("f", show f)
              ]
         ) rows

encodeDimensionRowsJson :: [(Double, Double)] -> String
encodeDimensionRowsJson rows =
  jsonArray $
    fmap (\(q, dim) ->
            jsonObject
              [ ("q", show q)
              , ("dim", show dim)
              ]
         ) rows

jsonObject :: [(String, String)] -> String
jsonObject fields =
  "{"
    ++ L.intercalate "," (fmap (\(k, v) -> jsonString k ++ ":" ++ v) fields)
    ++ "}"

jsonArray :: [String] -> String
jsonArray values = "[" ++ L.intercalate "," values ++ "]"

jsonString :: String -> String
jsonString str = "\"" ++ concatMap escapeJson str ++ "\""

escapeJson :: Char -> String
escapeJson '"' = "\\\""
escapeJson '\\' = "\\\\"
escapeJson '\b' = "\\b"
escapeJson '\f' = "\\f"
escapeJson '\n' = "\\n"
escapeJson '\r' = "\\r"
escapeJson '\t' = "\\t"
escapeJson c = [c]

extractSingleAddr :: [ByteString] -> ByteString
extractSingleAddr (addr:_) = addr
extractSingleAddr [] = error "Expected at least one column in each input row"

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
