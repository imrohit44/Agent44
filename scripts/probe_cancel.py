import asyncio


async def inner():
    try:
        await asyncio.sleep(30)
    finally:
        print("inner done (should not print)")


async def decide():
    try:
        raw = await asyncio.wait_for(inner(), timeout=0.1)
        print("wait_for returned:", raw)
    except asyncio.TimeoutError:
        print("decide saw TimeoutError from wait_for")
    except asyncio.CancelledError:
        print("decide saw CancelledError")
        raise


async def main():
    loop = asyncio.get_running_loop()
    task = loop.create_task(decide())
    await asyncio.sleep(0.05)
    task.cancel()
    try:
        await task
        print("outer task completed normally")
    except asyncio.CancelledError:
        print("outer task was cancelled")
    except Exception as exc:
        print("outer task raised:", type(exc).__name__, exc)


asyncio.run(main())
