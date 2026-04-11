from typing import Any

from sigma.conditions import ConditionAND, ConditionOR
from sigma.modifiers import SigmaFieldReferenceModifier
from sigma.rule import SigmaDetection, SigmaDetectionItem, SigmaRule

from sigma_rule_matcher_local.condition import Condition
from sigma_rule_matcher_local.detection_evaluator import DetectionEvaluator
from sigma_rule_matcher_local.missing_field import MissingField
from sigma_rule_matcher_local.utils import get_by_dots


class RuleMatcher:

    _missing_field = MissingField()

    def __init__(self, rule: SigmaRule):
        self.rule = rule

        if len(self.rule.detection.condition) != 1:
            raise ValueError("Only a single condition value is expected")

        if len(self.rule.detection.detections.keys()) == 0:
            raise ValueError("No selectors found")

        self._condition: Condition = Condition(
            condition=self.rule.detection.condition[0],
            selectors=set(self.rule.detection.detections.keys()),
        )

        self.detection_items: dict[int, DetectionEvaluator] = {}

        # register all leaf SigmaDetectionItems, recursing into nested SigmaDetections
        for symbol in self._condition.get_symbols():
            detection = self.rule.detection.detections[str(symbol)]
            self._register_items(detection)

    def _register_items(self, detection: SigmaDetection):
        """Recursively register all leaf SigmaDetectionItems into self.detection_items."""
        for item in detection.detection_items:
            if isinstance(item, SigmaDetection):
                self._register_items(item)  # nested — recurse
            else:
                self.detection_items[id(item)] = DetectionEvaluator(item)  # leaf

    def get_rule_condition(self) -> Condition:
        return self._condition

    def match(self, event: dict[str, Any]) -> bool:
        expression = self.get_rule_condition().get_instance()

        for symbol in self.get_rule_condition().get_symbols():
            detection = self.rule.detection.detections[symbol]

            selector_result = self._evaluate_detection_group(event, detection)

            result = expression.evaluate(symbol=symbol, value=selector_result)

            if isinstance(result, bool):
                return result

        return False

    def _evaluate_detection_group(self, event: dict[str, Any], detection: SigmaDetection) -> bool:
        """Evaluate a detection group, recursing into nested SigmaDetection objects."""
        results = []

        for item in detection.detection_items:
            if isinstance(item, SigmaDetection):
                # nested detection (e.g. from "1 of them" / "all of them" expansion)
                results.append(self._evaluate_detection_group(event, item))
            else:
                # leaf SigmaDetectionItem
                results.append(self._evaluate_selector_item(event, item))

        if not results:
            return False

        # respect item_linking: AND = all must match, OR = any must match
        if detection.item_linking is ConditionAND:
            return all(results)
        else:
            return any(results)  # ConditionOR or None defaults to OR

    def _evaluate_selector_item(self, event: dict[str, Any], detection_item: SigmaDetectionItem) -> bool:

        event_value = get_by_dots(event, detection_item.field, self._missing_field)

        if event_value and not isinstance(event_value, str | int | float | MissingField):
            raise NotImplementedError(f"Unknown input value type detected, type: '{type(event_value)}'.")

        if SigmaFieldReferenceModifier in detection_item.modifiers:
            if len(detection_item.value) != 1:
                raise NotImplementedError("only a single value allowed for field1")

            target_field_key = str(detection_item.value[0].field)
            target_field_value = get_by_dots(event, target_field_key, self._missing_field)

            return event_value == target_field_value

        new_matcher = self.detection_items.get(id(detection_item))

        if not new_matcher:
            raise RuntimeError(f"No matcher found for field {detection_item.field}")

        return new_matcher.match(event_value)