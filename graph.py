from pyvis.network import Network

def build_graph(results):
    net = Network(height="500px", width="100%", bgcolor="#0e1117", font_color="white")

    for res in results:
        domain = res["domain"]

        # Color based on risk
        color = "green"
        if res["risk"] == "HIGH":
            color = "orange"
        elif res["risk"] == "CRITICAL":
            color = "red"

        net.add_node(domain, label=domain, color=color)

        for sub in res.get("subdomains", []):
            net.add_node(sub, label=sub, color="orange")
            net.add_edge(domain, sub)

            for port in res.get("ports", []):
                port_node = f"{sub}:{port}"
                net.add_node(port_node, label=f"Port {port}", color="cyan")
                net.add_edge(sub, port_node)

    net.save_graph("graph.html")
    return "graph.html"
