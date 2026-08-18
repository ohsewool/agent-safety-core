"""Declared equivalences: loosening a binding must be deliberate and recorded."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.binding import STRICT, ArgumentPolicy, BindingError, Equivalence


class TestStrictByDefault:
    def test_identical_calls_bind_the_same(self):
        assert STRICT.equivalent({"amount": 1000}, {"amount": 1000})

    def test_a_changed_value_is_a_different_call(self):
        assert not STRICT.equivalent({"amount": 1000}, {"amount": 2000})

    def test_key_order_is_not_a_difference(self):
        """Canonicalisation already handles this; declaring it would be noise."""
        assert STRICT.equivalent({"a": 1, "b": 2}, {"b": 2, "a": 1})

    @pytest.mark.parametrize("first,second", [
        ({"amount": 1000}, {"amount": 1000.0}),
        ({"tags": ["a", "b"]}, {"tags": ["b", "a"]}),
        ({"note": "hello"}, {"note": " hello "}),
        ({"name": "Alice"}, {"name": "alice"}),
    ])
    def test_nothing_is_loosened_without_being_asked(self, first, second):
        assert not STRICT.equivalent(first, second)


class TestDeclaredEquivalences:
    def test_numeric_equivalence_accepts_int_and_float(self):
        policy = ArgumentPolicy({"amount": Equivalence.NUMERIC})
        assert policy.equivalent({"amount": 1000}, {"amount": 1000.0})

    def test_numeric_equivalence_still_separates_different_amounts(self):
        policy = ArgumentPolicy({"amount": Equivalence.NUMERIC})
        assert not policy.equivalent({"amount": 1000}, {"amount": 1000.01})

    def test_unordered_equivalence_ignores_sequence_order(self):
        policy = ArgumentPolicy({"tags": Equivalence.UNORDERED})
        assert policy.equivalent({"tags": ["a", "b"]}, {"tags": ["b", "a"]})

    def test_unordered_equivalence_still_notices_a_changed_member(self):
        policy = ArgumentPolicy({"tags": Equivalence.UNORDERED})
        assert not policy.equivalent({"tags": ["a", "b"]}, {"tags": ["a", "c"]})

    def test_unordered_equivalence_notices_a_duplicate(self):
        """A multiset, not a set: sending twice is not the same as sending once."""
        policy = ArgumentPolicy({"tags": Equivalence.UNORDERED})
        assert not policy.equivalent({"tags": ["a"]}, {"tags": ["a", "a"]})

    def test_trimmed_equivalence_ignores_surrounding_whitespace(self):
        policy = ArgumentPolicy({"note": Equivalence.TRIMMED})
        assert policy.equivalent({"note": "hello"}, {"note": "  hello  "})

    def test_trimmed_equivalence_keeps_interior_whitespace(self):
        policy = ArgumentPolicy({"note": Equivalence.TRIMMED})
        assert not policy.equivalent({"note": "a b"}, {"note": "ab"})

    def test_case_folding_is_available_where_it_is_correct(self):
        policy = ArgumentPolicy({"name": Equivalence.CASE_FOLDED})
        assert policy.equivalent({"name": "Alice"}, {"name": "ALICE"})


class TestScopedLoosening:
    def test_a_rule_applies_only_to_the_argument_it_names(self):
        policy = ArgumentPolicy({"amount": Equivalence.NUMERIC})
        assert not policy.equivalent({"amount": 1000, "fee": 5},
                                     {"amount": 1000, "fee": 5.0})

    def test_rules_compose(self):
        policy = (ArgumentPolicy()
                  .with_rule("amount", Equivalence.NUMERIC)
                  .with_rule("tags", Equivalence.UNORDERED))
        assert policy.equivalent({"amount": 1000, "tags": ["a", "b"]},
                                 {"amount": 1000.0, "tags": ["b", "a"]})


class TestPolicyIsBound:
    def test_the_same_call_binds_differently_under_a_looser_policy(self):
        """Relaxing a rule after approval would widen what the approval permitted."""
        call = {"amount": 1000}
        assert STRICT.digest_of(call) != ArgumentPolicy(
            {"amount": Equivalence.NUMERIC}
        ).digest_of(call)

    def test_adding_an_unrelated_rule_also_changes_the_binding(self):
        call = {"amount": 1000}
        loosened = ArgumentPolicy({"note": Equivalence.TRIMMED})
        assert STRICT.digest_of(call) != loosened.digest_of(call)

    def test_the_policy_can_be_shown_to_a_reviewer(self):
        policy = ArgumentPolicy({"amount": Equivalence.NUMERIC,
                                 "tags": Equivalence.UNORDERED})
        assert policy.describe() == {"amount": "numeric", "tags": "unordered"}


class TestMisapplication:
    def test_numeric_equivalence_on_a_string_is_refused(self):
        policy = ArgumentPolicy({"amount": Equivalence.NUMERIC})
        with pytest.raises(BindingError) as error:
            policy.digest_of({"amount": "1000"})
        assert "amount" in str(error.value)

    def test_numeric_equivalence_rejects_booleans(self):
        """True is not 1 here; treating it as a number hides a type confusion."""
        policy = ArgumentPolicy({"flag": Equivalence.NUMERIC})
        with pytest.raises(BindingError):
            policy.digest_of({"flag": True})

    def test_unordered_equivalence_on_a_scalar_is_refused(self):
        policy = ArgumentPolicy({"tags": Equivalence.UNORDERED})
        with pytest.raises(BindingError):
            policy.digest_of({"tags": "a,b"})

    def test_trimming_a_number_is_refused(self):
        policy = ArgumentPolicy({"note": Equivalence.TRIMMED})
        with pytest.raises(BindingError):
            policy.digest_of({"note": 5})

    def test_a_non_equivalence_rule_is_refused_at_construction(self):
        with pytest.raises(BindingError):
            ArgumentPolicy({"amount": "numeric"})

    def test_unbindable_values_are_still_refused(self):
        with pytest.raises(BindingError):
            STRICT.digest_of({"amount": float("nan")})


class TestOrderStability:
    def test_unordered_sorting_is_stable_across_mixed_types(self):
        policy = ArgumentPolicy({"items": Equivalence.UNORDERED})
        first = {"items": [1, "a", True, None]}
        second = {"items": [None, True, "a", 1]}
        assert policy.equivalent(first, second)

    def test_nested_structures_survive_unordered_comparison(self):
        policy = ArgumentPolicy({"items": Equivalence.UNORDERED})
        assert policy.equivalent({"items": [{"a": 1}, {"b": 2}]},
                                 {"items": [{"b": 2}, {"a": 1}]})
