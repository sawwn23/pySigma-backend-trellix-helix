from sigma.processing.conditions import LogsourceCondition
from sigma.processing.transformations import AddConditionTransformation, FieldMappingTransformation, DetectionItemFailureTransformation, RuleFailureTransformation, SetStateTransformation, ChangeLogsourceTransformation
from sigma.processing.conditions import LogsourceCondition, IncludeFieldCondition, ExcludeFieldCondition, RuleProcessingItemAppliedCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.rule import SigmaDetectionItem
from sigma.exceptions import SigmaTransformationError

class InvalidTransformation(DetectionItemFailureTransformation):
    def apply_detection_item(self, detection_item: SigmaDetectionItem) -> None:
        fiele_name = detection_item.field
        self.message = f"Invalid fieldname encounter: {fiele_name}." + self.message
        raise SigmaTransformationError(self.message)

def trellix_helix_pipeline() -> ProcessingPipeline:
    translation_dict = {
        'process_creation':{
            "EventId"
            "ProcessGuid":"processguid",
            "ProcessId":"pid",
            "Image":"process",
            "CommandLine":"args",
            "CurrentDirectory":"",
            "User":"username",
            "LogonGuid":"logonguid",
            "LogonId":"loginid",
            "TerminalSessionId":"sessionid",
            "IntegrityLevel":"integritylevel",
            "imphash":"imphash",
            "md5":"md5",
            "sha256":"sha256",
            "ParentProcessGuid":"pprocessguid",
            "ParentProcessId":"ppid",
            "ParentImage":"pprocess",
            "ParentCommandLine":"pargs"
        }
        #need to add other events
    }

    object_class_filter = [
        # Add Class = ms_windows_event
        ProcessingItem(
            identifier="trellix_class_windows",
            transformation=AddConditionTransformation({
                "class": "ms_windows_event"
            }),
            rule_conditions=[
                LogsourceCondition(product="windows")
            ]
        )
        # need to add other class
    ]

    object_eventlog_filter = [
        # Add Category = Process Create
        ProcessingItem(
            identifier="trellix_process_creation_eventtype",
            transformation=AddConditionTransformation({
                "category": "process create"
            }),
            rule_conditions=[
                LogsourceCondition(category="process_creation")
            ]
        )
        # need to add others category
    ]

    fields_mappings = [
        # Process Creation
        ProcessingItem(
            identifier="helix_process_creation_mapping",
            transformation=FieldMappingTransformation(translation_dict['process_creation']),
            rule_conditions=[
                LogsourceCondition(category="process_creation")
            ]
        )
        # more stuff
    ]

    # change_logsource_info = [
    #     # Add service to be SentinelOne for pretty much everything
    #     ProcessingItem(
    #         identifier="helix_logsource",
    #         transformation=ChangeLogsourceTransformation(
    #             service="sentinelone"
    #         ),
    #         rule_condition_linking=any,
    #         rule_conditions=[
    #             LogsourceCondition(category="process_creation"),
    #             LogsourceCondition(category="file_change"),
    #             LogsourceCondition(category="file_rename"),
    #             LogsourceCondition(category="file_delete"),
    #             LogsourceCondition(category="file_event"),
    #             LogsourceCondition(category="image_load"),
    #             LogsourceCondition(category="pipe_creation"),
    #             LogsourceCondition(category="registry_add"),
    #             LogsourceCondition(category="registry_delete"),
    #             LogsourceCondition(category="registry_event"),
    #             LogsourceCondition(category="registry_set"),
    #             LogsourceCondition(category="dns"),
    #             LogsourceCondition(category="dns_query"),
    #             LogsourceCondition(category="network_connection"),
    #             LogsourceCondition(category="firewall")
    #         ]
    #     ),
    # ]

    # unsupported_rule_types = [
    #     # Show error if unsupported option
    #     ProcessingItem(
    #         identifier="helix_fail_rule_not_supported",
    #         rule_condition_linking=any,
    #         transformation=RuleFailureTransformation("Rule type not yet supported by the Helix Sigma backend"),
    #         rule_condition_negation=True,
    #         rule_conditions=[
    #             RuleProcessingItemAppliedCondition("s1_logsource")
    #         ]
    #     )
    # ]

    # unsupported_field_name = [
    #     ProcessingItem(
    #         identifier='s1_fail_field_not_supported',
    #         transformation=InvalidFieldTransformation("This pipeline only supports the following fields:\n{" + 
    #         '}, {'.join(sorted(set(
    #             list(_flatten([[k,v] for t in translation_dict.keys() for k, v in
    #                            translation_dict[t].items()])) + general_supported_fields
    #         )))),
    #         field_name_conditions=[
    #             ExcludeFieldCondition(fields=list(set(
    #                 list(_flatten([[k, v] for t in translation_dict.keys() for k, v in
    #                                translation_dict[t].items()])) + general_supported_fields
    #             )))
    #         ]
    #     )
    # ]

    return ProcessingPipeline(
        name="Trellix_Helix pipeline",
        priority=50,
        items = [
            # *unsupported_field_name,
            *object_class_filter,
            *object_eventlog_filter,
            *fields_mappings,
            # *change_logsource_info,
            # *unsupported_rule_types,
        ]
    )
