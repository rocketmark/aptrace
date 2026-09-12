{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}
-- | An APTrace-owned interpretation layer over Macaw's own
-- @'MDP.ParsedCall'@ terminator, exposing the real ISA-level semantics of
-- the actual terminating instruction -- because, on this firmware, Macaw's
-- generic AArch32 call classifier is measurably over-inclusive: auditing
-- all 48 @kind = \"indirect\"@ @ParsedCall@ sites against Macaw's own
-- decoded instruction and link-register (@_R14@) behavior found only 23
-- were genuine register-indirect calls (@BLX@, LR freshly set to a return
-- address, Macaw's own @mret@ field @Just@); the other 25 were plain
-- same-function branches or jump tables (@CBZ@\/@CBNZ@, @TBB@\/@TBH@, a
-- direct @LDR@ into @PC@, or a computed @BX@ tail-call) that never touch
-- LR at all, misrouted through the call classifier.
--
-- This module never decodes instruction bytes itself and never consults
-- Ghidra\/Capstone\/dynamic evidence: it reads Macaw's own
-- 'MC.InstructionStart' statement -- part of the lifted block Macaw itself
-- already produced, carrying \"the disassembler output if available\" as
-- Macaw's own Haddock puts it -- for the block's terminating instruction,
-- and combines that with Macaw's own return-address field
-- (@ParsedCall@\'s second argument) to decide the ISA-level category.
-- Never mutates or replaces the original @ParsedCall@\/@CallInfo@
-- evidence; this is a strictly additive interpretation of the exact same
-- lifted block.
module APTrace.MacawIsaClassify
  ( SemanticKind(..)
  , semanticKindText
  , aptraceIsaClassificationProvenance
  , IsaClassification(..)
  , classifyParsedCall
  ) where

import qualified Data.Text as Text
import           Data.Word ( Word32 )

import qualified Data.Macaw.ARM as ARM
import qualified Data.Macaw.CFG as MC
import qualified Data.Macaw.Memory as MM

-- | The ISA-level category a @ParsedCall@ terminator's actual terminating
-- instruction really belongs to. @Ambiguous@ is the safe fallback: an
-- instruction family this module does not recognize, or Macaw's own
-- return-address field disagreeing with what the mnemonic family would
-- predict (e.g. a @BLX@ with no return address, or a @BX@ with one) --
-- reported rather than guessed at.
data SemanticKind
  = TrueIndirectCall
    -- ^ @BL@\/@BLX@ family: LR is freshly (re-)established as a return
    -- address, and Macaw's own @mret@ is @Just@. A genuine, expected-to-
    -- return, register-indirect (or PC-relative) call.
  | TailCall
    -- ^ @BX@ family: control transfers to a computed address with no
    -- return expected back here (Macaw's own @mret@ is @Nothing@,
    -- matching @BX@\'s architectural definition, which never writes LR).
    -- A genuine inter-procedural transfer, just not one that comes back.
  | ConditionalBranch
    -- ^ @CBZ@\/@CBNZ@: an ordinary same-function two-way conditional
    -- branch. Never a call, regardless of how complex the branch
    -- condition's own data dependency is.
  | TableBranch
    -- ^ @TBB@\/@TBH@: a compiler-emitted switch-case jump table. Never a
    -- call.
  | ComputedJump
    -- ^ A direct load into @PC@ (e.g. @LDR Rt=PC@) -- a computed jump via
    -- an absolute-address table, distinct from @TBB@\/@TBH@\'s relative
    -- byte/halfword table encoding. Never a call.
  | Ambiguous
    -- ^ Recognized neither by mnemonic family nor by a return-address
    -- pattern consistent with one -- or no decoded instruction could be
    -- found for this terminator at all. Reported honestly rather than
    -- forced into one of the other categories.
  deriving (Eq, Show)

semanticKindText :: SemanticKind -> String
semanticKindText k = case k of
  TrueIndirectCall  -> "true_indirect_call"
  TailCall          -> "tail_call"
  ConditionalBranch -> "conditional_branch"
  TableBranch       -> "table_branch"
  ComputedJump      -> "computed_jump"
  Ambiguous         -> "ambiguous"

-- | The provenance tag every 'IsaClassification'-derived record must
-- carry -- this is APTrace's own interpretation of Macaw's lifted IR, not
-- base Macaw evidence and not Ghidra's.
aptraceIsaClassificationProvenance :: String
aptraceIsaClassificationProvenance = "aptrace-isa-classification"

data IsaClassification = IsaClassification
  { icInstructionAddr :: !Word32
    -- ^ The canonical address of the actual terminating instruction --
    -- not necessarily the block's own start address, if the block has
    -- leading straight-line code before it.
  , icInstruction     :: !String
    -- ^ The bare mnemonic (e.g. @\"BLX_r_T1\"@) Macaw's own
    -- 'MC.InstructionStart' recorded for that instruction, with the
    -- trailing bit-pattern\/operand text dropped.
  , icSemanticKind    :: !SemanticKind
  } deriving (Eq, Show)

-- | The last 'MC.InstructionStart' statement in a block's own statement
-- list is, by construction, the terminating instruction whose successor
-- effects (curIP\/LR) the block's terminator describes: Macaw emits
-- exactly one 'MC.InstructionStart' per real machine instruction, in
-- program order, each carrying that instruction's own disassembler-output
-- text verbatim -- never re-derived, decoded, or guessed at here.
lastInstruction :: [MC.Stmt ARM.ARM ids] -> Maybe (MM.MemWord 32, Text.Text)
lastInstruction stmts =
  case [ (off, mnem) | MC.InstructionStart off mnem <- stmts ] of
    [] -> Nothing
    xs -> Just (last xs)

-- | Classify one @ParsedCall@ terminator's actual terminating instruction.
-- @blockStart@ is the block's own canonical start address (used only to
-- turn the instruction's block-relative offset into an absolute address);
-- @stmts@ is that same block's own statement list; @mret@ is Macaw's own
-- @ParsedCall@ return-address field for this exact terminator.
classifyParsedCall
  :: Word32
  -> [MC.Stmt ARM.ARM ids]
  -> Maybe (MM.MemSegmentOff 32)
  -> IsaClassification
classifyParsedCall blockStart stmts mret =
  case lastInstruction stmts of
    Nothing -> IsaClassification blockStart "(no decoded instruction found)" Ambiguous
    Just (off, mnemText) ->
      let addr = blockStart + fromIntegral (MM.memWordValue off)
          -- Macaw formats this Text as "<addr>: <mnemonic> (<operand fields>)"
          -- (see macaw-aarch32's Disassemble.hs, @printf "%s: %s"@); strip the
          -- leading disassembly address before matching the mnemonic family.
          afterAddr = case Text.breakOn ": " mnemText of
            (_, rest) | not (Text.null rest) -> Text.drop 2 rest
            _                                -> mnemText
          mnem = Text.dropWhile (== ' ') (Text.takeWhile (/= '(') afterAddr)
          hasReturn = case mret of
            Just _  -> True
            Nothing -> False
          kind
            | "BL" `Text.isPrefixOf` mnem  = if hasReturn then TrueIndirectCall else Ambiguous
            | "BX" `Text.isPrefixOf` mnem  = if hasReturn then Ambiguous else TailCall
            | "CBZ" `Text.isPrefixOf` mnem || "CBNZ" `Text.isPrefixOf` mnem = ConditionalBranch
            | "TBB" `Text.isPrefixOf` mnem || "TBH" `Text.isPrefixOf` mnem = TableBranch
            | "LDR" `Text.isPrefixOf` mnem && "Rt 15" `Text.isInfixOf` afterAddr = ComputedJump
            | otherwise = Ambiguous
      in IsaClassification addr (Text.unpack mnem) kind
