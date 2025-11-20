from typing import List, Optional
from .scanner import run_scan
from .metrics import calculate_metrics
from .models import ScanResult
from .config import Config


def orchestrate_scan(targets: List[str], config: Optional[Config] = None, tn: int = 0) -> dict:

    if config is None:
        config = Config.load()

    scan_results: List[ScanResult] = []
    failed_targets = []

    print(f"\n{'=' * 50}")
    print(f" Iniciando escaneo de {len(targets)} target(s)")
    print(f"{'=' * 50}\n")

    for idx, target in enumerate(targets, 1):
        print(f"[{idx}/{len(targets)}]  Escaneando: {target}")
        try:
            result = run_scan(target, config)
            scan_results.append(result)
            print(f"     Completado: {len(result.findings)} finding(s)\n")
        except Exception as e:
            failed_targets.append(target)
            print(f"     ERROR: {e}\n")

    print(f"\n{'=' * 50}")
    print(" Calculando métricas...")
    print(f"{'=' * 50}")

    metrics = calculate_metrics(scan_results, tn=tn)

    total_findings = sum(len(r.findings) for r in scan_results)
    total_files = sum(r.summary.get("files_analyzed", 0) for r in scan_results)

    print(f"\n{'=' * 50}")
    print("RESUMEN GENERAL")
    print(f"{'=' * 50}")
    print(f"Targets exitosos: {len(scan_results)}/{len(targets)}")
    if failed_targets:
        print(f"Targets fallidos: {len(failed_targets)}")
        for ft in failed_targets:
            print(f"   - {ft}")
    print(f" Archivos analizados: {total_files}")
    print(f"Total findings: {total_findings}")
    print(f"{'=' * 50}\n")

    return {
        "metrics": metrics,
        "summary": {
            "total_targets": len(targets),
            "successful_targets": len(scan_results),
            "failed_targets": len(failed_targets),
            "total_files_analyzed": total_files,
            "total_findings": total_findings
        },
        "scan_results": scan_results
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Orquestador de escaneo SAST")
    parser.add_argument(
        "targets",
        nargs="+",
        help="Archivos o carpetas a escanear"
    )
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Ruta al archivo de configuración YAML"
    )
    parser.add_argument(
        "--tn",
        type=int,
        default=0,
        help="Número de True Negatives para métricas"
    )
    args = parser.parse_args()

    config = Config.load(args.config) if args.config else None

    results = orchestrate_scan(args.targets, config=config, tn=args.tn)

    print("\nMÉTRICAS FINALES")
    print("=" * 50)
    for k, v in results["metrics"].items():
        if isinstance(v, float):
            print(f"{k:.<30} {v:.4f}")
        else:
            print(f"{k:.<30} {v}")