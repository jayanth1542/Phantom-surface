import asyncio

COMMON_PORTS = [21,22,23,25,53,80,110,139,143,443,445,3306,3389,8080]

async def scan_port(host, port):
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=1)
        writer.close()
        await writer.wait_closed()
        return port
    except:
        return None

async def scan_ports_async(host):
    tasks = [scan_port(host, p) for p in COMMON_PORTS]
    results = await asyncio.gather(*tasks)
    return [p for p in results if p]

def scan_ports(host):
    try:
        return asyncio.run(scan_ports_async(host))
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(scan_ports_async(host))
