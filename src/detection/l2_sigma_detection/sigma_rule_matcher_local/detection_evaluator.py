import fnmatch
import ipaddress
import re
from collections.abc import Callable
from enum import Enum, auto
print("LOADING PATCHED detection_evaluator.py")
from sigma.conditions import ConditionOR
from sigma.modifiers import (
    SigmaBase64Modifier,
    SigmaBase64OffsetModifier,
    SigmaCaseSensitiveModifier,
    SigmaRegularExpression,
    SigmaRegularExpressionModifier,
)
from sigma.rule import SigmaDetectionItem
from sigma.types import (
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaExpansion,
    SigmaFieldReference,
    SigmaNull,
    SigmaNumber,
    SigmaString,
    SpecialChars,
    SigmaBool,          # ← add
)

from sigma_rule_matcher_local.missing_field import MissingField


class EvaluatorPriority(Enum):
    # Checks will be executed in this order.
    EXISTS = auto()  # This always needs to be first.
    EQUALS = auto()
    NUMERIC = auto()
    REGEX = auto()
    WILDCARD = auto()
    CIDR = auto()


DetectionInputValue = str | int | float | None | MissingField

DetectionEvaluatorFunction = Callable[[DetectionInputValue], bool]
PrioritisedEvaluator = tuple[EvaluatorPriority, DetectionEvaluatorFunction]


class DetectionEvaluator:

    def __init__(self, item: SigmaDetectionItem):
        self.item: SigmaDetectionItem = item

        # Base64 and regex modifiers are always case-sensitive
        self.cased = any(modifier in item.modifiers for modifier in (
            SigmaCaseSensitiveModifier,
            SigmaBase64Modifier,
            SigmaBase64OffsetModifier,
            SigmaRegularExpressionModifier,
        ))

        evaluators = self._initialise_evaluators(item.value)

        # Sort by EvaluatorPriority weight
        self.evaluators = sorted(evaluators, key=lambda x: x[0].value)

    def _initialise_evaluators(self, options: list) -> list[PrioritisedEvaluator]:
        evaluators: list[PrioritisedEvaluator] = []

        # Collect plain equals values separately so we can do O(1) set lookup
        equals: list[SigmaNumber | SigmaString] = []

        for option in options:
            
            if isinstance(option, SigmaString):
                if SpecialChars.WILDCARD_MULTI in option.s or SpecialChars.WILDCARD_SINGLE in option.s:
                    evaluators.append((EvaluatorPriority.WILDCARD, self.create_wildcard_evaluator(option, self.cased)))
                else:
                    equals.append(option)

            elif isinstance(option, SigmaNumber):
                equals.append(option)

            elif isinstance(option, SigmaRegularExpression):
                # Fixed: use option.regexp instead of option.escape() which doesn't exist in modern pySigma
                evaluators.append((EvaluatorPriority.REGEX, self.create_regex_evaluator(option)))

            elif isinstance(option, SigmaCompareExpression):
                evaluators.append((EvaluatorPriority.NUMERIC, self.create_numeric_evaluator(option)))

            elif isinstance(option, SigmaExpansion):
                # Recurse into expansion values and merge results
                evaluators.extend(self._initialise_evaluators(option.values))

            elif isinstance(option, SigmaCIDRExpression):
                evaluators.append((EvaluatorPriority.CIDR, self.create_cidr_evaluator(option)))

            elif isinstance(option, SigmaExists):
                evaluators.append((EvaluatorPriority.EXISTS, self.create_exists_evaluator(option)))

            elif isinstance(option, SigmaNull):
                # Field is explicitly checked for null/missing — e.g. "field: null" in the rule
                
                evaluators.append((EvaluatorPriority.EXISTS, self.create_null_evaluator()))
            elif isinstance(option, SigmaBool):   # ← add this
                evaluators.append((EvaluatorPriority.EQUALS, self.create_bool_evaluator(option)))

            elif isinstance(option, SigmaFieldReference):
                # Handled separately in matcher.py via SigmaFieldReferenceModifier — skip here
                pass
        
            else:
              
                print(f"  type: {type(option)}")
                print(f"  type mro: {type(option).__mro__}")
                print(f"  SigmaNull is: {SigmaNull}")
                print(f"  isinstance check: {isinstance(option, SigmaNull)}")
                raise NotImplementedError(f"No implementation for for type: {type(option)}")
                          

        if len(equals) > 0:
            evaluators.append((EvaluatorPriority.EQUALS, self.create_equals_evaluator(equals, self.cased)))

        return evaluators

    def match(self, value: DetectionInputValue) -> bool:
        if len(self.evaluators) == 0:
            return False

        # EXISTS checks run first and need no value
        for t, modifier in self.evaluators:
            if t != EvaluatorPriority.EXISTS:
                break
            if modifier(value):
                return True

        # No other checks apply if value is missing
        if value is None or isinstance(value, MissingField):
            return False

        if isinstance(value, str) and not self.cased:
            value = value.casefold()

        if self.item.value_linking == ConditionOR:
            # Any one match is sufficient
            for _, modifier in self.evaluators:
                if modifier(value):
                    return True
            return False

        # All must match (AND linking)
        for _, modifier in self.evaluators:
            if not modifier(value):
                return False

        return True

    # ----------------------------------------------------------------------------------------------

    @staticmethod
    def create_equals_evaluator(options: list[SigmaString | SigmaNumber], cased: bool) -> DetectionEvaluatorFunction:
        targets: set[str | int | float] = set()
        for option in options:
            if isinstance(option, SigmaString):
                target = str(option) if cased else str(option).casefold()
            else:
                target = option.number
            targets.add(target)

        def check(value: DetectionInputValue, targets=targets) -> bool:
            return value in targets

        return check

    @staticmethod
    def create_wildcard_evaluator(option: SigmaString, cased: bool) -> DetectionEvaluatorFunction:
        option = str(option) if cased else str(option).casefold()

        star_count = option.count("*")
        question_count = option.count("?")

        if question_count == 0 and star_count == 2 and option.startswith("*") and option.endswith("*"):  # noqa: PLR2004
            # contains
            def check(value: DetectionInputValue, target=option[1:-1]) -> bool:
                return target in value

        elif question_count == 0 and star_count == 1 and option.endswith("*"):
            # startswith
            def check(value: DetectionInputValue, target=option[:-1]) -> bool:
                return value.startswith(target)

        elif question_count == 0 and star_count == 1 and option.startswith("*"):
            # endswith
            def check(value: DetectionInputValue, target=option[1:]) -> bool:
                return value.endswith(target)

        else:
            regex = re.compile(fnmatch.translate(option))

            def check(value: DetectionInputValue, pattern=regex) -> bool:
                return bool(pattern.search(value))

        return check

    @staticmethod
    def create_numeric_evaluator(option: SigmaCompareExpression) -> DetectionEvaluatorFunction:
        target = option.number.number

        if option.op == SigmaCompareExpression.CompareOperators.GT:
            def check(value: DetectionInputValue) -> bool:
                return value > target
        elif option.op == SigmaCompareExpression.CompareOperators.LT:
            def check(value: DetectionInputValue) -> bool:
                return value < target
        elif option.op == SigmaCompareExpression.CompareOperators.GTE:
            def check(value: DetectionInputValue) -> bool:
                return value >= target
        elif option.op == SigmaCompareExpression.CompareOperators.LTE:
            def check(value: DetectionInputValue) -> bool:
                return value <= target
        else:
            raise NotImplementedError("Numeric comparison operator is not supported")

        return check

    @staticmethod
    def create_regex_evaluator(option: SigmaRegularExpression) -> DetectionEvaluatorFunction:
        # option.regexp returns a SigmaString in some pySigma versions — convert to plain str
        pattern = re.compile(str(option.regexp))

        def check(value: DetectionInputValue) -> bool:
            if not isinstance(value, str):
                value = str(value)
            return bool(pattern.search(value))

        return check

    @staticmethod
    def create_cidr_evaluator(option: SigmaCIDRExpression) -> DetectionEvaluatorFunction:
        network = ipaddress.ip_network(option.cidr, strict=False)

        def check(value: DetectionInputValue) -> bool:
            try:
                ip = ipaddress.ip_address(value)
            except ValueError:
                return False
            else:
                return ip in network

        return check

    @staticmethod
    def create_exists_evaluator(option: SigmaExists) -> DetectionEvaluatorFunction:
        should_field_exist = bool(option)

        def check(value: DetectionInputValue) -> bool:
            if should_field_exist and not isinstance(value, MissingField):
                return True
            return not should_field_exist and isinstance(value, MissingField)

        return check

    @staticmethod
    def create_null_evaluator() -> DetectionEvaluatorFunction:
        """Matches when the field value is explicitly null or not present in the event."""
        def check(value: DetectionInputValue) -> bool:
            return value is None or isinstance(value, MissingField)

        return check
    @staticmethod
    def create_bool_evaluator(option: SigmaBool) -> DetectionEvaluatorFunction:
        """Matches when the field value equals the expected boolean."""
        # SigmaBool wraps a Python bool — extract it
        expected = bool(option)
    
        def check(value: DetectionInputValue) -> bool:
            if isinstance(value, bool):
                return value == expected
            if isinstance(value, str):
                return value.lower() in ("true", "1") if expected else value.lower() in ("false", "0")
            if isinstance(value, int):
                return bool(value) == expected
            return False
    
        return check