"""LangGraph assembly and checkpoint configuration."""

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph

from app.coreAgents.orchestration.executor import execute_response
from app.coreAgents.orchestration.nodes import (
    create_final_report,
    handle_failure,
    initialize_investigation,
    load_wazuh_alert,
    mark_awaiting_approval,
    mark_response_approved,
    normalize_alert,
    prepare_actions,
    request_human_approval,
    run_l1,
    run_l2,
    run_l3,
)
from app.coreAgents.orchestration.routing import (
    route_after_l1,
    route_after_l2,
    route_after_action_policy,
    route_after_approval,
    route_after_step,
)
from app.coreAgents.orchestration.state import InvestigationState


def create_investigation_graph(
    *,
    gateway=None,
    l1_agent=None,
    l2_agent=None,
    l3_agent=None,
    l1_team=None,
    l2_team=None,
    l3_team=None,
    checkpointer=None,
    responder=None,
    system_executor=None,
    response_settings=None,
    clock=None,
):
    """Compile the read-only investigation graph with checkpoint persistence."""

    def load_alert_node(state: InvestigationState) -> dict:
        return load_wazuh_alert(state, gateway=gateway)

    legacy_agents_supplied = any(
        item is not None for item in (l1_agent, l2_agent, l3_agent)
    )
    teams_supplied = any(
        item is not None for item in (l1_team, l2_team, l3_team)
    )
    if legacy_agents_supplied and teams_supplied:
        raise ValueError("Inject either tier agents or tier teams, not both.")

    if legacy_agents_supplied:
        def l1_node(state: InvestigationState) -> dict:
            return run_l1(state, agent=l1_agent)

        def l2_node(state: InvestigationState) -> dict:
            return run_l2(state, agent=l2_agent)

        def l3_node(state: InvestigationState) -> dict:
            return run_l3(state, agent=l3_agent)

        l1_workflow = l1_node
        l2_workflow = l2_node
        l3_workflow = l3_node
    else:
        from app.coreAgents.orchestration.soc_teams import (
            create_l1_team,
            create_l2_team,
            create_l3_team,
        )

        l1_workflow = l1_team or create_l1_team(gateway=gateway)
        l2_workflow = l2_team or create_l2_team(gateway=gateway)
        l3_workflow = l3_team or create_l3_team(gateway=gateway)

    def response_executor_node(state: InvestigationState) -> dict:
        return execute_response(
            state,
            responder=responder,
            system_executor=system_executor,
            settings_obj=response_settings,
            now=clock,
        )

    builder = StateGraph(InvestigationState)
    builder.add_node("initialize", initialize_investigation)
    builder.add_node("load_alert", load_alert_node)
    builder.add_node("normalize_alert", normalize_alert)
    builder.add_node("l1_triage", l1_workflow)
    builder.add_node("l2_investigation", l2_workflow)
    builder.add_node("l3_analysis", l3_workflow)
    builder.add_node("prepare_actions", prepare_actions)
    builder.add_node("awaiting_approval", mark_awaiting_approval)
    builder.add_node("human_approval", request_human_approval)
    builder.add_node("response_approved", mark_response_approved)
    builder.add_node("response_executor", response_executor_node)
    builder.add_node("final_report", create_final_report)
    builder.add_node("failed", handle_failure)

    builder.add_edge(START, "initialize")
    builder.add_conditional_edges(
        "initialize",
        lambda state: route_after_step(state, success_node="load_alert"),
        {"load_alert": "load_alert", "failed": "failed"},
    )
    builder.add_conditional_edges(
        "load_alert",
        lambda state: route_after_step(state, success_node="normalize_alert"),
        {"normalize_alert": "normalize_alert", "failed": "failed"},
    )
    builder.add_conditional_edges(
        "normalize_alert",
        lambda state: route_after_step(state, success_node="l1_triage"),
        {"l1_triage": "l1_triage", "failed": "failed"},
    )
    builder.add_conditional_edges(
        "l1_triage",
        route_after_l1,
        {
            "l2_investigation": "l2_investigation",
            "final_report": "final_report",
            "failed": "failed",
        },
    )
    builder.add_conditional_edges(
        "l2_investigation",
        route_after_l2,
        {
            "l3_analysis": "l3_analysis",
            "final_report": "final_report",
            "failed": "failed",
        },
    )
    builder.add_edge("l3_analysis", "prepare_actions")
    builder.add_conditional_edges(
        "prepare_actions",
        route_after_action_policy,
        {
            "awaiting_approval": "awaiting_approval",
            "final_report": "final_report",
            "failed": "failed",
        },
    )
    builder.add_edge("awaiting_approval", "human_approval")
    builder.add_conditional_edges(
        "human_approval",
        route_after_approval,
        {
            "response_approved": "response_approved",
            "prepare_actions": "prepare_actions",
            "final_report": "final_report",
            "failed": "failed",
        },
    )
    builder.add_edge("response_approved", "response_executor")
    builder.add_conditional_edges(
        "response_executor",
        lambda state: route_after_step(
            state,
            success_node="final_report",
        ),
        {"final_report": "final_report", "failed": "failed"},
    )
    builder.add_edge("final_report", END)
    builder.add_edge("failed", END)

    return builder.compile(
        checkpointer=checkpointer if checkpointer is not None else InMemorySaver()
    )


def investigation_config(investigation_id: str) -> dict:
    if not investigation_id:
        raise ValueError("investigation_id is required.")
    return {"configurable": {"thread_id": investigation_id}}
