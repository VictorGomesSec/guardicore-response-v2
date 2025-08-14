def rule_modification_template(rule: dict, indicators: list[str]) -> dict:
    fields_to_not_include = [
        "author",
        "creation_time",
        "hit_count",
        "hit_count_reset_time",
        "id",
        "last_change_time",
        "last_hit",
        "read_only",
        "state",
    ]
    fields_to_process_manually = [
        "attributes",
        "worksite",
        "scope",
        "source",
        "destination",
    ]

    rule_modified = {
        "attributes": {
            "worksite": rule["attributes"]["worksite"]["id"],
        },
        "scope": [scope["id"] for scope in rule["scope"]],
        "source": {},
        "destination": {},
    }

    for key, value in rule.items():
        if key in fields_to_not_include:
            continue
        if key in fields_to_process_manually:
            continue
        rule_modified[key] = value

    source = rule["source"]

    if subnets := source.get("subnets"):
        rule_modified["source"]["subnets"] = subnets
    if processes := source.get("processes"):
        rule_modified["source"]["processes"] = processes
    if address_classification := source.get("address_classification"):
        rule_modified["source"]["address_classification"] = address_classification
    if label_groups := source.get("label_groups"):
        rule_modified["source"]["label_group_ids"] = [
            label_group["id"] for label_group in label_groups
        ]
    if assets := source.get("assets"):
        rule_modified["source"]["asset_ids"] = [asset["id"] for asset in assets]
    if labels := source.get("labels"):
        rule_modified["source"]["labels"] = {}
        rule_modified["source"]["labels"]["or_labels"] = []
        for or_label in labels["or_labels"]:
            rule_modified["source"]["labels"]["or_labels"].append(
                {
                    "and_labels": [
                        and_label["id"] for and_label in or_label["and_labels"]
                    ]
                }
            )

    destination = rule["destination"]
    if processes := destination.get("processes"):
        rule_modified["destination"]["processes"] = processes

    rule_modified["destination"]["subnets"] = indicators

    return rule_modified


def publish_policy_revision_template(ruleset_name: str, comments: str) -> dict:
    return {
        "comments": comments,
        "reset_hit_count": False,
        "ruleset_name": ruleset_name,
    }
