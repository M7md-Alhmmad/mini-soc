import argparse


def build_parser():
    parser = argparse.ArgumentParser(
        prog="mini-soc",
        description="Run the Mini SOC dashboard, monitor, detector, or simulators."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    serve = subparsers.add_parser("serve", help="Start the API and web dashboard")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", default=8000, type=int)

    subparsers.add_parser("monitor", help="Monitor newly inserted events")
    subparsers.add_parser("detect", help="Scan all stored events once")

    simulate = subparsers.add_parser("simulate", help="Insert a safe attack scenario")
    simulate.add_argument(
        "scenario",
        choices=("brute-force", "port-scan", "account-compromise")
    )
    simulate.add_argument("--username", default=None)
    simulate.add_argument("--ip", default=None)
    simulate.add_argument("--count", type=int, default=None)

    generate = subparsers.add_parser("generate", help="Generate benign sample events")
    generate.add_argument("--count", type=int, default=25)
    return parser


def main():
    args = build_parser().parse_args()

    if args.command == "serve":
        import uvicorn
        uvicorn.run("src.api:app", host=args.host, port=args.port)
    elif args.command == "monitor":
        from .main import monitor_soc
        monitor_soc()
    elif args.command == "detect":
        from .detection_engine import run_detection
        run_detection()
    elif args.command == "generate":
        from .log_generator import generate_logs
        if args.count < 1:
            raise SystemExit("--count must be at least 1")
        generate_logs(args.count)
    else:
        from .attack_simulator import (
            simulate_account_compromise,
            simulate_brute_force,
            simulate_port_scan,
        )

        defaults = {
            "brute-force": ("admin", "203.0.113.50", 10),
            "port-scan": ("scanner", "198.51.100.25", 20),
            "account-compromise": ("admin", "203.0.113.50", 10),
        }
        username, ip_address, count = defaults[args.scenario]
        username = args.username or username
        ip_address = args.ip or ip_address
        count = args.count if args.count is not None else count
        if count < 1:
            raise SystemExit("--count must be at least 1")

        if args.scenario == "brute-force":
            simulate_brute_force(username, ip_address, count)
        elif args.scenario == "port-scan":
            simulate_port_scan(username, ip_address, count)
        else:
            simulate_account_compromise(username, ip_address, count)


if __name__ == "__main__":
    main()
