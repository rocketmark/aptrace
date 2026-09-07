-- | Parsing of the standard ARMv7-M vector table found at the start of a
-- Cortex-M firmware image (or application image, if a bootloader precedes
-- it -- see the flash-base argument passed by the caller).
module APTrace.VectorTable
  ( VectorEntry(..)
  , parseVectorTable
  ) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import           Data.Binary.Get ( runGet, getWord32le )
import           Data.Word ( Word32 )

-- | One non-empty entry in the vector table.
data VectorEntry = VectorEntry
  { veIndex   :: Int
    -- ^ Word index into the table (1 = Reset_Handler, 15 = SysTick_Handler,
    -- 16+ = external interrupt N = index - 16).
  , veName    :: String
  , veRawAddr :: Word32
    -- ^ The raw table value. For Thumb handlers (the only kind Cortex-M
    -- has) this has the low (Thumb) bit set; callers should generally hand
    -- this raw value to Macaw's code discovery unmodified -- see
    -- 'APTrace.FirmwareLoader.resolveEntry'.
  } deriving (Show, Eq)

systemHandlerNames :: [String]
systemHandlerNames =
  [ "Initial_SP", "Reset_Handler", "NMI_Handler", "HardFault_Handler"
  , "MemManage_Handler", "BusFault_Handler", "UsageFault_Handler"
  , "Reserved_7", "Reserved_8", "Reserved_9", "Reserved_10"
  , "SVC_Handler", "DebugMon_Handler", "Reserved_13"
  , "PendSV_Handler", "SysTick_Handler"
  ]

nameForIndex :: Int -> String
nameForIndex i
  | i < length systemHandlerNames = systemHandlerNames !! i
  | otherwise = "IRQ" ++ show (i - length systemHandlerNames) ++ "_Handler"

-- | Parse a vector table located at the start of the given bytes. Returns
-- every non-zero handler entry, skipping index 0 (the initial stack
-- pointer, which is a RAM address, not a code entry point). Reserved slots
-- that happen to be zero (the normal case) are simply absent from the
-- result; a non-zero reserved slot is still returned (as an anomaly the
-- caller may want to flag, but not itself fatal).
parseVectorTable :: Int          -- ^ Number of external IRQ vectors to read after the 16 system handlers
                  -> BS.ByteString -- ^ Firmware bytes, vector table at offset 0
                  -> [VectorEntry]
parseVectorTable numIrq bs =
  [ VectorEntry i (nameForIndex i) w
  | (i, w) <- zip [0 :: Int ..] rawWords
  , i > 0
  , w /= 0
  ]
  where
    total = 16 + numIrq
    rawWords = runGet (sequence (replicate total getWord32le)) (LBS.fromStrict bs)
