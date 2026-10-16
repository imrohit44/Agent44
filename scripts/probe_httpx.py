import inspect
import httpx

print("httpx version:", httpx.__version__)

# Probe Response.aclose and AsyncClient.send cancellation cleanup.
src = inspect.getsource(httpx.Response.aclose)
print("--- Response.aclose ---")
print(src)

# Print the relevant part of AsyncClient.send to understand how cancellation
# interacts with stream reading and aclose.
try:
    src_send = inspect.getsource(httpx.AsyncClient.send)
    print("--- AsyncClient.send (first 1500 chars) ---")
    print(src_send[:1500])
except Exception as exc:
    print("could not get send source:", exc)
