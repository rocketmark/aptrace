-- | Performing Rigs AutoPilot/Remote target configuration: the single
-- authoritative definition of this product's ATSAMD51J19A (Cortex-M4F,
-- 192KB RAM) memory geometry. Every module that previously duplicated
-- these numbers as its own local constants ('APTrace.MacawCensus',
-- 'APTrace.MacawExpand', 'APTrace.DebugHarness', @app/Main.hs@) now takes
-- them as parameters supplied from here instead, so reusable framework
-- code carries no Performing Rigs-specific knowledge of its own -- see
-- @docs/architecture.md@'s framework/case split.
--
-- This is deliberately a handful of plain top-level values, not a record
-- or a configuration framework: there is exactly one target in this
-- project today, and a plugin-style abstraction over a single case would
-- be speculative generality this refactor is not chartered to add.
module APTrace.Case.PerformingRigs
  ( ramBase
  , ramSize
  , numIrq
  , defaultFlashBase
  , mmioWindow
  ) where

import Data.Word ( Word32 )

-- | RAM base address for the AutoPilot/Remote ATSAMD51J19A target.
ramBase :: Word32
ramBase = 0x20000000

-- | RAM size (192KB) for the AutoPilot/Remote ATSAMD51J19A target.
ramSize :: Word32
ramSize = 0x30000

-- | External (NVIC) IRQ vector count for the ATSAMD51J19A: the vector
-- table is 16 system words followed by this many IRQ words. Equal to the
-- case SVD's highest interrupt number plus one (IRQ0..135); the Python
-- side derives the same value from the SVD (@NUM_EXTERNAL_IRQ@ in
-- @cases/performing-rigs/config/performing_rigs.py@), and
-- @cases/performing-rigs/test/test_target_irq_count.py@ fails if the two
-- drift. Was 40, which silently dropped every vector above IRQ39 (USB,
-- most SERCOM, TCC/TC).
numIrq :: Int
numIrq = 136

-- | Performing Rigs firmware images are linked to start at flash 0x4000
-- (past the bootloader) -- the default every CLI subcommand falls back to
-- when the caller doesn't override it.
defaultFlashBase :: Word32
defaultFlashBase = 0x4000

-- | The peripheral (MMIO) address window for this target, as (base, size).
-- Mirrors @CENSUS_MMIO_BASE@/@CENSUS_MMIO_SIZE@ in
-- @cases/performing-rigs/config/performing_rigs.py@ (the census's own
-- classification window); the agent's function-effects action checks the
-- window reported in each result against the census build's recorded
-- geometry, so a drift between the two is detected rather than silent.
mmioWindow :: (Word32, Word32)
mmioWindow = (0x40000000, 0x4000000)
