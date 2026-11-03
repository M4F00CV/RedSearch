"""ReAct loop: the core agent execution engine.

Reads responses from the LLM, extracts tool calls (native or via
text fallback), dispatches them, and feeds results back to the
model until it produces a final answer or hits max_iterations.
"""

import json
import re
from pathlib import Path

from src.core.llm import chat_with_tools
from src.core.utils import (
    extract_tool_calls_from_text,
    is_stuck_in_loop,
    is_stuck_within,
    normalize_args,
)
from src.tools.registry import TOOL_MAP, TOOLS

SYSTEM_PROMPT = (
    "Eres un agente de análisis de seguridad. Tienes herramientas disponibles. "
    "Cuando necesites información o realizar una acción, llama a la herramienta adecuada.\n\n"
    "REGLAS CRÍTICAS — VIOLARLAS INVALIDA TU RESPUESTA:\n"
    "- NUNCA inventes el contenido de un archivo. Si necesitas leer código, usa read_file_tool.\n"
    "- NUNCA afirmes que ejecutaste una acción (ej. 'reporte generado', 'archivo escrito') "
    "si no llamaste explícitamente a la herramienta correspondiente en este turno. "
    "Si necesitas escribir un reporte, USA write_report_tool — no lo describas como hecho.\n"
    "- Si el objetivo pide varias acciones, ejecútalas UNA POR UNA en iteraciones separadas, "
    "esperando el resultado de cada una.\n"
    "- NO emitas múltiples tool calls en el mismo turno si dependen entre sí.\n"
    "- Cuando uses una herramienta, cita en el resumen final: check_id, línea y severidad "
    "tal como aparecen en la observación.\n"
    "- Si el objetivo NO pide explícitamente escribir un archivo, responde con texto en el chat "
    "sin usar write_report_tool.\n"
    "- Si no puedes cumplir una parte del objetivo, dilo explícitamente."
)


def run_agent(goal: str, max_iter: int = 6) -> None:
    """Execute the ReAct loop against a goal.

    Args:
        goal: Natural language objective for the agent.
        max_iter: Hard limit on iterations to prevent infinite loops.
    """
    print(f"\n{'='*60}")
    print(f"OBJETIVO: {goal}")
    print(f"{'='*60}")

    seen_calls = set()
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": goal},
    ]

    previous_content = ""
    consecutive_no_action = 0

    for iteration in range(1, max_iter + 1):
        print(f"\n--- Iteración {iteration} ---")
        response = chat_with_tools(
            messages, TOOLS, force_tool=(consecutive_no_action >= 1)
        )
        msg = response["choices"][0]["message"]

        content = (msg.get("content") or "").strip()
        if content:
            print(f"[THOUGHT] {content[:300]}{'...' if len(content) > 300 else ''}")

        if is_stuck_in_loop(content, previous_content) or is_stuck_within(content):
            print("\n[ABORT] Bucle detectado (inter o intra-turno). Abortando.")
            print(f"         Último tool call exitoso: {list(seen_calls)[-1] if seen_calls else 'ninguno'}")
            return
        previous_content = content

        tool_calls = msg.get("tool_calls") or []
        fallback_list = []

        if not tool_calls:
            fallback_list = extract_tool_calls_from_text(content)
            if fallback_list:
                print(f"[FALLBACK] {len(fallback_list)} tool call(s) extraídos de texto")
                tool_calls = []
                for idx, fb in enumerate(fallback_list):
                    call_id = f"call_{iteration}_{idx}"
                    tool_calls.append({
                        "id": call_id,
                        "type": "function",
                        "function": {
                            "name": fb.get("name", ""),
                            "arguments": json.dumps(fb.get("arguments", {})),
                        },
                    })
                messages.append({
                    "role": "assistant",
                    "content": "",
                    "tool_calls": tool_calls,
                })
                consecutive_no_action = 0
            else:
                consecutive_no_action += 1

                claimed_files = re.findall(r"reports/[\w\-\.]+\.md", content)
                missing = [f for f in claimed_files if not Path(f).exists()]

                if claimed_files and not missing:
                    print("\n[FINAL] Objetivo completado (archivos verificados).")
                    print(content)
                    return

                if missing:
                    print(f"\n[ALERTA] El modelo afirma haber generado {missing}, pero no existen.")
                    print("         (posible alucinación de acción)")

                if consecutive_no_action >= 2 and seen_calls:
                    print(f"\n[FINAL] Resumen tras {len(seen_calls)} herramienta(s) ejecutada(s).")
                    print(content or "(respuesta vacía)")
                    return

                if consecutive_no_action >= 2 and not seen_calls:
                    print("\n[ABORT] Sin acción ejecutada tras reintentos. Abortando.")
                    print(content or "(respuesta vacía)")
                    return

                print("[RETRY] Forzando tool call en el próximo turno.")
                messages.append({"role": "assistant", "content": content})
                messages.append({
                    "role": "user",
                    "content": "Debes llamar a una herramienta ahora. No respondas con texto sin acción.",
                })
                continue

        for tc in tool_calls:
            fn = tc.get("function", {})
            name = fn.get("name")
            args = fn.get("arguments", {})

            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {}

            if isinstance(args, dict):
                args = normalize_args(name, args)
            else:
                args = {}

            call_key = (name, json.dumps(args, sort_keys=True))
            if call_key in seen_calls:
                result = "(ya ejecutado antes en esta sesión con los mismos argumentos; no repetir)"
                print(f"[OBSERVATION] {result}")
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.get("id", f"call_{iteration}"),
                    "content": result,
                })
                continue
            seen_calls.add(call_key)

            print(f"[ACTION] {name}({json.dumps(args, ensure_ascii=False)})")

            if name in TOOL_MAP:
                try:
                    result = TOOL_MAP[name](**args)
                except Exception as e:
                    result = f"Error ejecutando {name}: {e}"
            else:
                result = f"Herramienta desconocida: {name}"

            print(f"[OBSERVATION] {str(result)[:300]}{'...' if len(str(result)) > 300 else ''}")

            messages.append({
                "role": "tool",
                "tool_call_id": tc.get("id", f"call_{iteration}"),
                "content": str(result),
            })

    if seen_calls:
        print(f"\n[FINAL] Se agotaron {max_iter} iteraciones. "
              f"{len(seen_calls)} herramienta(s) ejecutada(s).")
    else:
        print(f"\n[LÍMITE] {max_iter} iteraciones sin ejecutar ninguna herramienta.")