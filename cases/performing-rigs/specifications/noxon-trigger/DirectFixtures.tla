-------------------------- MODULE DirectFixtures --------------------------
DirectFixtures == [n \in {"program-causal-repeat", "program-g-trigger-high", "program-without-g", "program-g-duplicate-sequence"} |-> CASE n="program-causal-repeat" -> [hasG |-> TRUE, sequence |-> 1, readsync |-> TRUE, target |-> 500, current |-> 0, rate |-> 8119, expected |-> <<0, 30, 500, 8119>>, arm |-> 2, phase |-> 1]
 [] n="program-g-trigger-high" -> [hasG |-> TRUE, sequence |-> 1, readsync |-> TRUE, target |-> 500, current |-> 0, rate |-> 8119, expected |-> <<0, 30, 500, 8119>>, arm |-> 2, phase |-> 1]
 [] n="program-without-g" -> [hasG |-> FALSE, sequence |-> 0, readsync |-> TRUE, target |-> 500, current |-> 0, rate |-> 8119, expected |-> <<>>, arm |-> 0, phase |-> 0]
 [] n="program-g-duplicate-sequence" -> [hasG |-> TRUE, sequence |-> 0, readsync |-> TRUE, target |-> 500, current |-> 0, rate |-> 8119, expected |-> <<>>, arm |-> 0, phase |-> 0]]
=============================================================================
