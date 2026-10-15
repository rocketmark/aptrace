-- SPIKE ONLY: print Macaw's discovered IR (after APTrace's MacawExpand
-- classify-failure recovery) for the blocks of one function
-- that overlap an address window. usage:
--   runghc DumpBlocks.hs IMAGE FLASH_BASE ENTRY LO HI
{-# LANGUAGE ScopedTypeVariables #-}
module Main (main) where

import qualified Data.ByteString as BS
import qualified Data.Map as Map
import           Data.Parameterized.Some ( Some(..) )
import           Lens.Micro ( (^.) )
import           Numeric ( readHex )
import qualified Prettyprinter as PP
import           System.Environment ( getArgs )

import qualified Data.Macaw.CFG as MC
import qualified Data.Macaw.Discovery as MD
import qualified Data.Macaw.Memory as MM

import           APTrace.MacawExpand ( expandWithNormalization, ExpansionResult(..), RoundInfo(..) )
import           APTrace.FirmwareLoader ( buildMemory, resolveEntry, macawCortexMEntry, armCortexMInfo )

hex :: String -> Integer
hex s = fst (head (readHex (if take 2 s == "0x" then drop 2 s else s)))

main :: IO ()
main = do
  [path, baseS, entS, loS, hiS] <- getArgs
  bs <- BS.readFile path
  let Right mem = buildMemory bs (fromInteger (hex baseS)) 0x20000000 0x30000
      Just ent = resolveEntry mem (macawCortexMEntry (fromInteger (hex entS)))
      st0 = MD.cfgFromAddrs armCortexMInfo mem Map.empty [ent] []
      er = expandWithNormalization mem st0
      st = erExpandedState er
      lo = hex loS
      hi = hex hiS
  case Map.lookup ent (st ^. MD.funInfo) of
    Nothing -> putStrLn "function not discovered"
    Just (Some fi) -> do
      putStrLn ("rounds: " ++ show (length (erRounds er)) ++ " resolutions: " ++ show (sum (map (length . riResolutions) (erRounds er))))
      putStrLn ("blocks: " ++ show (Map.size (fi ^. MD.parsedBlocks)))
      mapM_ (\b -> do
              let a = maybe 0 toInteger (MM.segoffAsAbsoluteAddr (MD.pblockAddr b))
              if a >= lo && a <= hi then print (PP.pretty b) else pure ())
            (Map.elems (fi ^. MD.parsedBlocks))
