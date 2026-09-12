{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
-- | One small, APTrace-owned normalization rule over Macaw's own lifted IR,
-- applied only when handling a Macaw @ClassifyFailure@ curIP expression:
-- the Boolean identity
--
-- > mux(c, mux(c, A, B), C) == mux(c, A, C)
--
-- and its symmetric form
--
-- > mux(c, A, mux(c, B, C)) == mux(c, A, C)
--
-- both valid for /any/ architecture's Mux semantics whenever the two
-- conditions are the exact same value: whichever way @c@ resolves, the
-- inner mux (evaluated at that same @c@) reduces to exactly one of its own
-- branches, making the other branch of the inner mux (@B@ above) dead and
-- collapsing the whole expression to a flat two-way branch on @c@ alone.
-- This is pure Boolean substitution, not an architecture- or
-- instruction-specific rewrite.
--
-- This module never decodes instruction bytes, never consults
-- Ghidra\/Capstone, and never modifies Macaw. It tests condition identity
-- via 'MC.Value'\'s own 'Eq' instance (backed by Macaw's own
-- 'MC.AssignId' identity), never pretty-printed text -- see
-- @docs/tooling/...@ investigation notes on the 72 @classify_failure@
-- blocks this addresses 49 of. A recovered target is only ever accepted
-- when it is a concrete address that resolves into this firmware's own
-- mapped memory via 'resolveEntry' -- the exact same resolution every
-- other discovery root and call target in this project goes through -- so
-- a recovered target is canonicalized identically to everywhere else and
-- is never OR'd with 1 or otherwise special-cased.
module APTrace.MacawNormalize
  ( macawNormalizedProvenance
  , normalizeIP
  , normalizeIPSegOff
  , segOffToCanonicalWord
  ) where

import qualified Data.List as List
import           Data.Word ( Word32 )

import qualified Data.Macaw.ARM as ARM
import qualified Data.Macaw.CFG as MC
import qualified Data.Macaw.Memory as MM
import qualified Data.Macaw.Types as MT

import           APTrace.FirmwareLoader ( resolveEntry )

-- | The provenance tag every recovered target in the census must carry --
-- never relabeled as ordinary @macaw-base@ evidence.
macawNormalizedProvenance :: String
macawNormalizedProvenance = "macaw-normalized"

-- | Peel one 'MC.Mux' off a value, if it directly is one -- the same typed
-- check ('MC.valueAsApp') macaw-aarch32's own classifiers use, without its
-- architecture-specific simplification step (irrelevant here: this module
-- implements exactly one, different, architecture-independent identity of
-- its own, and does not rely on macaw-aarch32 having already simplified
-- anything).
asMux
  :: MC.Value ARM.ARM ids (MT.BVType 32)
  -> Maybe ( MC.Value ARM.ARM ids MT.BoolType
           , MC.Value ARM.ARM ids (MT.BVType 32)
           , MC.Value ARM.ARM ids (MT.BVType 32)
           )
asMux v = case MC.valueAsApp v of
  Just (MC.Mux _ c t f) -> Just (c, t, f)
  _                     -> Nothing

-- | A concrete address that resolves into this firmware's own mapped
-- memory, as the 'MM.MemSegmentOff' Macaw's own discovery API expects --
-- 'Nothing' for anything else (a register, another mux, a memory read, an
-- unmapped literal, ...), so normalization safely declines rather than
-- guessing. Mirrors 'APTrace.MacawCensus.callsOf'\'s own
-- @MC.valueAsMemAddr ipVal >>= MM.asAbsoluteAddr@ idiom for extracting a
-- concrete address from a curIP-shaped value, then resolves it exactly like
-- every other address in this project (no bit manipulation of its own).
-- The literal addresses Macaw's own lifted IR uses for a direct branch
-- target are already canonical (even), so this never needs to touch a
-- Thumb bit itself.
asConcreteMappedSegOff :: MM.Memory 32 -> MC.Value ARM.ARM ids (MT.BVType 32) -> Maybe (MM.MemSegmentOff 32)
asConcreteMappedSegOff mem v = do
  addr <- MC.valueAsMemAddr v
  w <- MM.asAbsoluteAddr addr
  resolveEntry mem (fromIntegral (MM.memWordValue w))

-- | The canonical (even) Cortex-M instruction address for a resolved
-- 'MM.MemSegmentOff' -- the same operation
-- 'APTrace.MacawCensus.canonicalWord' performs, duplicated here (it is a
-- four-line, purely mechanical unwrap with no policy of its own) so this
-- module has no import-cycle dependency on 'APTrace.MacawCensus'.
segOffToCanonicalWord :: MM.MemSegmentOff 32 -> Word32
segOffToCanonicalWord off =
  case MM.asAbsoluteAddr (MM.segoffAddr (MM.clearSegmentOffLeastBit off)) of
    Just w  -> fromIntegral (MM.memWordValue w)
    Nothing -> error "segOffToCanonicalWord: expected an absolute address"

-- | Attempt the one supported identity on a @ClassifyFailure@ block's curIP
-- value. Returns the (one or two, deduplicated) recovered concrete targets,
-- as the 'MM.MemSegmentOff' values Macaw's own
-- @Data.Macaw.Discovery.addDiscoveredFunctionBlockTargets@ expects, on
-- success; 'Nothing' whenever any safety condition fails -- the value isn't
-- a mux at all, the two conditions differ, or either surviving branch
-- isn't a concrete mapped address -- in which case the caller must leave
-- the original classify_failure as the sole evidence.
normalizeIPSegOff :: MM.Memory 32 -> MC.Value ARM.ARM ids (MT.BVType 32) -> Maybe [MM.MemSegmentOff 32]
normalizeIPSegOff mem ipVal = do
  (cond, t, f) <- asMux ipVal
  (survivorT, survivorF) <- case (asMux t, asMux f) of
    (Just (cond', a, _b), _) | cond == cond' -> Just (a, f)
    (_, Just (cond', _b, c)) | cond == cond' -> Just (t, c)
    _ -> Nothing
  offT <- asConcreteMappedSegOff mem survivorT
  offF <- asConcreteMappedSegOff mem survivorF
  Just (List.nub [offT, offF])

-- | Word32 form of 'normalizeIPSegOff', for consumers that only need the
-- (canonical, resolved) recovered addresses themselves -- e.g. the census's
-- own JSON output -- and not Macaw's own discovery-facing 'MM.MemSegmentOff'
-- representation.
normalizeIP :: MM.Memory 32 -> MC.Value ARM.ARM ids (MT.BVType 32) -> Maybe [Word32]
normalizeIP mem ipVal = map segOffToCanonicalWord <$> normalizeIPSegOff mem ipVal
