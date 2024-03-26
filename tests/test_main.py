import asgi_lifespan
import fastapi
import httpx
import respx
import pendulum
import pytest
import starlette

from armasec import Armasec
from plugin.main import request_cache


@pytest.fixture
async def app(rs256_domain):
    """
    Provides an instance of a FastAPI app that is to be used only for testing purposes.
    """
    app = fastapi.FastAPI()
    armasec = Armasec(domain=rs256_domain, audience="https://this.api", debug_logger=print)

    @app.get("/secured", dependencies=[fastapi.Depends(armasec.lockdown())])
    async def _():
        return dict(good="to go")

    @app.delete("/secured", dependencies=[fastapi.Depends(armasec.lockdown())])
    async def _():
        return dict(good="to go")

    return app


@pytest.fixture
async def client(app):
    """
    Provides a FastAPI client against which httpx requests can be made. Includes a "/secure"
    endpoint that requires auth via the TokenSecurity injectable.
    """
    async with asgi_lifespan.LifespanManager(app):
        async with httpx.AsyncClient(app=app, base_url="http://armasec-test") as client:
            yield client


async def test_armasec_plugin_check__success(
    mock_openid_server,
    build_rs256_token,
    app,
    client,
    mocker,
):
    """
    Test that the plugin works correctly by calling the `sub_check_url` and checking the
    return value.
    """
    request_cache.clear()
    with pendulum.travel_to("2024-03-19 16:19:00"):
        exp = pendulum.parse("2024-03-20 16:19:00", tz="UTC")
        token = build_rs256_token(claim_overrides=dict(sub="me", exp=exp.timestamp()))

        # Will skip plugin check because `sub_check_url` is not set by environment
        response = await client.get("/secured", headers={"Authorization": f"bearer {token}"})
        assert response.status_code == starlette.status.HTTP_200_OK

        # Will fail plugin check because `sub_check_url` returns a non 200 error code
        mocker.patch("plugin.main.sub_check_url", new="http://fake-url.com")
        with respx.mock:
            route = respx.get("http://fake-url.com")
            route.return_value = httpx.Response(starlette.status.HTTP_404_NOT_FOUND)
            response = await client.get("/secured", headers={"Authorization": f"bearer {token}"})
        assert response.status_code == starlette.status.HTTP_402_PAYMENT_REQUIRED

        # Will return with a 500 because the call to the route `sub_check_url` fails
        mocker.patch("plugin.main.sub_check_url", new="http://fake-url.com")
        with respx.mock():
            route = respx.get("http://fake-url.com")
            route.side_effect = Exception("BOOM!")
            response = await client.get("/secured", headers={"Authorization": f"bearer {token}"})
        assert response.status_code == starlette.status.HTTP_500_INTERNAL_SERVER_ERROR

        # Will pass plugin check because `sub_check_url` returns a 200 error code
        with respx.mock:
            route = respx.get("http://fake-url.com")
            route.return_value = httpx.Response(starlette.status.HTTP_200_OK)
            response = await client.get("/secured", headers={"Authorization": f"bearer {token}"})
        assert response.status_code == starlette.status.HTTP_200_OK


async def test_armasec_plugin_check__uses_cache(
    mock_openid_server,
    build_rs256_token,
    app,
    client,
    mocker,
):
    """
    Test that the plugin works correctly by calling the `sub_check_url` and checking the
    return value.
    """
    request_cache.clear()
    with pendulum.travel_to("2024-03-19 16:19:00"):
        exp = pendulum.parse("2024-03-20 16:19:00", tz="UTC")
        token = build_rs256_token(claim_overrides=dict(sub="me", exp=exp.timestamp()))

        mocker.patch("plugin.main.sub_check_url", new="http://fake-url.com")
        with respx.mock:
            route = respx.get("http://fake-url.com")
            route.return_value = httpx.Response(starlette.status.HTTP_200_OK)
            response = await client.get("/secured", headers={"Authorization": f"bearer {token}"})
        assert response.status_code == starlette.status.HTTP_200_OK

        # The endpoint is not called because the result is cached
        with respx.mock:
            route = respx.get("http://fake-url.com")
            route.side_effect = Exception("BOOM!")
            response = await client.get("/secured", headers={"Authorization": f"bearer {token}"})
        assert response.status_code == starlette.status.HTTP_200_OK

    with pendulum.travel_to("2024-03-19 18:19:00"):
        # The endpoint is called because the cached result is expired
        with respx.mock:
            route = respx.get("http://fake-url.com")
            route.side_effect = Exception("BOOM!")
            response = await client.get("/secured", headers={"Authorization": f"bearer {token}"})
        assert response.status_code == starlette.status.HTTP_500_INTERNAL_SERVER_ERROR


async def test_armasec_plugin_check__allow_reads(
    mock_openid_server,
    build_rs256_token,
    app,
    client,
    mocker,
):
    """
    Test that the plugin works correctly by skipping the call to the `sub_check_url` for
    GET endpoints when the `allow_reads` flag is set.
    """
    request_cache.clear()
    with pendulum.travel_to("2024-03-19 16:19:00"):
        exp = pendulum.parse("2024-03-20 16:19:00", tz="UTC")
        token = build_rs256_token(claim_overrides=dict(sub="me", exp=exp.timestamp()))

        # Will fail plugin check because `sub_check_url` returns a non 200 error code
        mocker.patch("plugin.main.sub_check_url", new="http://fake-url.com")
        with respx.mock:
            route = respx.get("http://fake-url.com")
            route.return_value = httpx.Response(starlette.status.HTTP_404_NOT_FOUND)
            response = await client.get("/secured", headers={"Authorization": f"bearer {token}"})
        assert response.status_code == starlette.status.HTTP_402_PAYMENT_REQUIRED

        # Will skip plugin check because `allow_reads` is set
        mocker.patch("plugin.main.allow_reads", new=True)
        with respx.mock:
            route = respx.get("http://fake-url.com")
            route.return_value = httpx.Response(starlette.status.HTTP_404_NOT_FOUND)
            response = await client.get("/secured", headers={"Authorization": f"bearer {token}"})
        assert response.status_code == starlette.status.HTTP_200_OK

        # Will fail plugin check because request is not a read and sub check fails
        with respx.mock:
            route = respx.get("http://fake-url.com")
            route.return_value = httpx.Response(starlette.status.HTTP_404_NOT_FOUND)
            response = await client.delete("/secured", headers={"Authorization": f"bearer {token}"})
        assert response.status_code == starlette.status.HTTP_402_PAYMENT_REQUIRED


async def test_armasec_plugin_check__allow_deletes(
    mock_openid_server,
    build_rs256_token,
    app,
    client,
    mocker,
):
    """
    Test that the plugin works correctly by skipping the call to the `sub_check_url` for
    DELETE endpoints when the `allow_deletes` flag is set.
    """
    request_cache.clear()
    with pendulum.travel_to("2024-03-19 16:19:00"):
        exp = pendulum.parse("2024-03-20 16:19:00", tz="UTC")
        token = build_rs256_token(claim_overrides=dict(sub="me", exp=exp.timestamp()))

        # Will fail plugin check because `sub_check_url` returns a non 200 error code
        mocker.patch("plugin.main.sub_check_url", new="http://fake-url.com")
        with respx.mock:
            route = respx.get("http://fake-url.com")
            route.return_value = httpx.Response(starlette.status.HTTP_404_NOT_FOUND)
            response = await client.delete("/secured", headers={"Authorization": f"bearer {token}"})
        assert response.status_code == starlette.status.HTTP_402_PAYMENT_REQUIRED

        # Will skip plugin check because `allow_deletes` is set
        mocker.patch("plugin.main.allow_deletes", new=True)
        with respx.mock:
            route = respx.get("http://fake-url.com")
            route.return_value = httpx.Response(starlette.status.HTTP_404_NOT_FOUND)
            response = await client.delete("/secured", headers={"Authorization": f"bearer {token}"})
        assert response.status_code == starlette.status.HTTP_200_OK

        # Will fail plugin check because request is not a delete and sub check fails
        with respx.mock:
            route = respx.get("http://fake-url.com")
            route.return_value = httpx.Response(starlette.status.HTTP_404_NOT_FOUND)
            response = await client.get("/secured", headers={"Authorization": f"bearer {token}"})
        assert response.status_code == starlette.status.HTTP_402_PAYMENT_REQUIRED
