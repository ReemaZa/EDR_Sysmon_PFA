import fnmatch
import re
from collections.abc import Callable

from boolean import AND, NOT, OR, BooleanAlgebra, Symbol
from boolean import Expression as BooleanExpression

from sigma_rule_matcher_local.condition_evaluator import (
    AndNotConditionEvaluator,
    DynamicBooleanEvaluator,
    BooleanConditionEvaluator,
    FalseConditionEvaluator,
    TrueConditionEvaluator,
    AndConditionEvaluator,
    OrConditionEvaluator,
    OrNotConditionEvaluator
)

ConditionEvaluatorFunction = Callable[[], BooleanConditionEvaluator]


class Condition:
    def __init__(self, condition: str, selectors: set[str]):
        condition_lower = condition.lower()

        # Replace ALL occurrences of "1 of them" and "all of them" with wildcard patterns
        # so the general "of" expansion below handles them uniformly.
        # This covers:
        #   condition: 1 of them                  → 1 of *
        #   condition: all of them                 → all of *
        #   condition: 1 of them and not filter    → 1 of * and not filter
        #   condition: all of them and not filter  → all of * and not filter
        condition = re.sub(r'1 of them', '1 of *', condition, flags=re.IGNORECASE)
        condition = re.sub(r'all of them', 'all of *', condition, flags=re.IGNORECASE)

        # ---

        # Expand "1|all of <pattern>" into explicit boolean expressions.
        # e.g. "1 of selection_*" → "(selection_1 OR selection_2)"
        # e.g. "all of selection_*" → "(selection_1 AND selection_2)"
        if "of " in condition.lower():
            matches = re.findall(r'((?:1|all) of ([\w?*]+))', condition, flags=re.IGNORECASE)

            for full_match, pattern in matches:
                matched_selectors: set[str] = set()
                for selector_name in selectors:
                    if fnmatch.fnmatch(selector_name, pattern):
                        matched_selectors.add(selector_name)

                if len(matched_selectors) == 0:
                    raise ValueError(f"No selectors matched '{full_match}'")

                logic = " AND " if full_match.lower().startswith("all") else " OR "
                of_condition = "(" + logic.join(matched_selectors) + ")"
                condition = condition.replace(full_match, of_condition)

        self._condition: BooleanExpression = BooleanAlgebra().parse(condition, simplify=True)
        self._symbols: list[Symbol] = self._condition.get_symbols()

        # ---

        # Validate that all referenced selectors exist.
        symbols = {str(s) for s in self._symbols}
        missing_selectors = symbols - selectors
        if len(missing_selectors) > 0:
            raise ValueError(f"Condition references selectors that are not present: {missing_selectors}")

        # ---

        evaluator = self._get_static_evaluator(self._condition)

        if evaluator is None:
            def get_instance() -> BooleanConditionEvaluator:
                return DynamicBooleanEvaluator(self._condition)
            evaluator = get_instance

        self.evaluator: ConditionEvaluatorFunction = evaluator

    @staticmethod
    def _get_static_evaluator(expr: BooleanExpression) -> ConditionEvaluatorFunction | None:
        len_symbols = len(expr.symbols)

        if len_symbols > 2:
            return None

        if len_symbols == 1:
            if isinstance(expr, NOT) and len(expr.args) == 1 and isinstance(expr.args[0], Symbol):
                def get_instance() -> BooleanConditionEvaluator:
                    return FalseConditionEvaluator(str(expr.args[0]))
            else:
                def get_instance() -> BooleanConditionEvaluator:
                    return TrueConditionEvaluator(str(expr))

            return get_instance

        if len_symbols == 2 and (isinstance(expr, AND) or isinstance(expr, OR)):
            left, right = expr.args

            if isinstance(left, Symbol) and isinstance(right, Symbol):
                if isinstance(expr, AND):
                    def get_instance() -> BooleanConditionEvaluator:
                        return AndConditionEvaluator(str(left), str(right))
                else:
                    def get_instance() -> BooleanConditionEvaluator:
                        return OrConditionEvaluator(str(left), str(right))
                return get_instance

            if not (isinstance(left, NOT) and isinstance(right, NOT)):
                if isinstance(right, NOT):
                    must_be_true, must_not_be_true = left, right.args[0]
                else:
                    must_be_true, must_not_be_true = right, left.args[0]

                if isinstance(expr, AND):
                    def get_instance() -> BooleanConditionEvaluator:
                        return AndNotConditionEvaluator(
                            symbol_that_must_be_true=str(must_be_true),
                            symbol_that_must_be_false=str(must_not_be_true)
                        )
                else:
                    def get_instance() -> BooleanConditionEvaluator:
                        return OrNotConditionEvaluator(
                            symbol_that_must_be_true=str(must_be_true),
                            symbol_that_must_be_false=str(must_not_be_true)
                        )
                return get_instance

        return None

    def get_expression(self) -> BooleanExpression:
        return self._condition

    def get_symbols(self) -> list[str]:
        return [str(s) for s in self._symbols]

    def get_instance(self) -> BooleanConditionEvaluator:
        return self.evaluator()