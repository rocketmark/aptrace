from aptrace_agent.router import route_question


def test_routes_incoming_call_query():
    plan = route_question(
        "What calls FUN_0000d3dc? Report the exact call-site addresses."
    )

    assert plan is not None
    assert len(plan.function_facts) == 1
    assert plan.function_facts[0].function == "FUN_0000d3dc"


def test_does_not_fake_route_complex_investigation():
    plan = route_question(
        "Is FUN_0000d3dc(1) involved in establishing the trigger baseline?"
    )

    assert plan is None
