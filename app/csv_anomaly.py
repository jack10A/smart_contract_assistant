import json
import os
from dataclasses import dataclass
from typing import Any

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import torch
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_groq import ChatGroq
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler
from torch import nn
from torch.utils.data import DataLoader, TensorDataset


MODEL_DIR = os.path.join("workspace_uploads", "models")
PLOT_DIR = os.path.join("workspace_uploads", "plots")
DEFAULT_EPOCHS = 20
DEFAULT_BATCH_SIZE = 32
RANDOM_SEED = 42


class Autoencoder(nn.Module):
    """Small fully connected autoencoder for tabular anomaly detection."""

    def __init__(self, input_dim: int):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 32),
            nn.ReLU(),
            nn.Linear(32, 16),
            nn.ReLU(),
            nn.Linear(16, 8),
            nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(8, 16),
            nn.ReLU(),
            nn.Linear(16, 32),
            nn.ReLU(),
            nn.Linear(32, input_dim),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.decoder(self.encoder(x))


@dataclass(frozen=True)
class PreprocessedCsv:
    raw_df: pd.DataFrame
    numeric_df: pd.DataFrame
    features: np.ndarray
    columns: list[str]
    scaler: StandardScaler


def _safe_artifact_name(file_path: str) -> str:
    name = os.path.splitext(os.path.basename(file_path))[0]
    safe = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in name)
    return safe or "csv_anomaly"


def _load_and_preprocess_csv(file_path: str) -> PreprocessedCsv:
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"CSV file not found: {file_path}")

    raw_df = pd.read_csv(file_path)
    numeric_df = raw_df.select_dtypes(include=[np.number]).copy()
    if numeric_df.empty:
        raise ValueError("CSV must contain at least one numeric column.")

    imputer = SimpleImputer(strategy="median")
    imputed = imputer.fit_transform(numeric_df)

    scaler = StandardScaler()
    scaled = scaler.fit_transform(imputed).astype(np.float32)

    clean_numeric_df = pd.DataFrame(imputed, columns=numeric_df.columns, index=raw_df.index)
    return PreprocessedCsv(
        raw_df=raw_df,
        numeric_df=clean_numeric_df,
        features=scaled,
        columns=list(numeric_df.columns),
        scaler=scaler,
    )


def _train_autoencoder(features: np.ndarray) -> tuple[Autoencoder, list[float]]:
    torch.manual_seed(RANDOM_SEED)
    input_dim = features.shape[1]
    model = Autoencoder(input_dim=input_dim)
    dataset = TensorDataset(torch.from_numpy(features))
    loader = DataLoader(dataset, batch_size=DEFAULT_BATCH_SIZE, shuffle=True)
    criterion = nn.MSELoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)

    model.train()
    losses: list[float] = []
    for _ in range(DEFAULT_EPOCHS):
        epoch_loss = 0.0
        for (batch,) in loader:
            optimizer.zero_grad()
            reconstructed = model(batch)
            loss = criterion(reconstructed, batch)
            loss.backward()
            optimizer.step()
            epoch_loss += loss.item() * batch.size(0)
        losses.append(epoch_loss / len(dataset))

    return model, losses


def _reconstruction_errors(model: Autoencoder, features: np.ndarray) -> np.ndarray:
    model.eval()
    with torch.no_grad():
        tensor = torch.from_numpy(features)
        reconstructed = model(tensor).numpy()
    return np.mean((features - reconstructed) ** 2, axis=1)


def _isolation_forest_anomalies(features: np.ndarray) -> set[int]:
    row_count = features.shape[0]
    if row_count < 4:
        return set()

    contamination = min(0.1, max(1 / row_count, 0.02))
    model = IsolationForest(
        contamination=contamination,
        random_state=RANDOM_SEED,
        n_estimators=100,
    )
    predictions = model.fit_predict(features)
    return {idx for idx, label in enumerate(predictions) if label == -1}


def _save_model(model: Autoencoder, file_path: str, columns: list[str], losses: list[float]) -> str:
    os.makedirs(MODEL_DIR, exist_ok=True)
    model_path = os.path.join(MODEL_DIR, f"{_safe_artifact_name(file_path)}_autoencoder.pt")
    torch.save(
        {
            "model_state_dict": model.state_dict(),
            "input_dim": len(columns),
            "columns": columns,
            "losses": losses,
            "architecture": "input -> 32 -> 16 -> 8 -> 16 -> 32 -> input",
        },
        model_path,
    )
    return model_path


def _plot_error_distribution(errors: np.ndarray, threshold: float, file_path: str) -> str:
    os.makedirs(PLOT_DIR, exist_ok=True)
    plot_path = os.path.join(PLOT_DIR, f"{_safe_artifact_name(file_path)}_reconstruction_errors.png")

    plt.figure(figsize=(8, 4.5))
    plt.hist(errors, bins=min(30, max(5, len(errors) // 2)), color="#2563eb", alpha=0.78)
    plt.axvline(threshold, color="#b42318", linestyle="--", linewidth=2, label="Threshold")
    plt.xlabel("Reconstruction error")
    plt.ylabel("Row count")
    plt.title("CSV reconstruction error distribution")
    plt.legend()
    plt.tight_layout()
    plt.savefig(plot_path, dpi=140)
    plt.close()

    return plot_path


def _plot_error_by_row(errors: np.ndarray, threshold: float, anomalies: list[int], file_path: str) -> str:
    os.makedirs(PLOT_DIR, exist_ok=True)
    plot_path = os.path.join(PLOT_DIR, f"{_safe_artifact_name(file_path)}_error_by_row.png")
    row_indices = np.arange(len(errors))

    plt.figure(figsize=(9, 4.8))
    plt.plot(row_indices, errors, color="#2563eb", linewidth=1.8, label="Reconstruction error")
    if anomalies:
        plt.scatter(anomalies, errors[anomalies], color="#b42318", s=48, label="Consensus anomalies", zorder=3)
    plt.axhline(threshold, color="#b42318", linestyle="--", linewidth=1.8, label="Threshold")
    plt.xlabel("CSV row index")
    plt.ylabel("Reconstruction error")
    plt.title("Reconstruction error by row")
    plt.legend()
    plt.tight_layout()
    plt.savefig(plot_path, dpi=140)
    plt.close()

    return plot_path


def _plot_top_scores(errors: np.ndarray, file_path: str, top_n: int = 15) -> str:
    os.makedirs(PLOT_DIR, exist_ok=True)
    plot_path = os.path.join(PLOT_DIR, f"{_safe_artifact_name(file_path)}_top_anomaly_scores.png")
    top_n = min(top_n, len(errors))
    top_indices = np.argsort(errors)[-top_n:][::-1]

    plt.figure(figsize=(9, 4.8))
    plt.bar([str(idx) for idx in top_indices], errors[top_indices], color="#0f8a52")
    plt.xlabel("CSV row index")
    plt.ylabel("Reconstruction error")
    plt.title(f"Top {top_n} anomaly scores")
    plt.tight_layout()
    plt.savefig(plot_path, dpi=140)
    plt.close()

    return plot_path


def _plot_correlation_heatmap(numeric_df: pd.DataFrame, file_path: str) -> str | None:
    if numeric_df.shape[1] < 2:
        return None

    os.makedirs(PLOT_DIR, exist_ok=True)
    plot_path = os.path.join(PLOT_DIR, f"{_safe_artifact_name(file_path)}_correlation_heatmap.png")
    corr = numeric_df.corr(numeric_only=True).fillna(0.0)

    plt.figure(figsize=(max(6, numeric_df.shape[1] * 0.75), max(5, numeric_df.shape[1] * 0.65)))
    image = plt.imshow(corr, cmap="coolwarm", vmin=-1, vmax=1)
    plt.colorbar(image, fraction=0.046, pad=0.04)
    plt.xticks(range(len(corr.columns)), corr.columns, rotation=45, ha="right")
    plt.yticks(range(len(corr.columns)), corr.columns)
    plt.title("Numeric column correlation heatmap")
    plt.tight_layout()
    plt.savefig(plot_path, dpi=140)
    plt.close()

    return plot_path


def _plot_numeric_histograms(numeric_df: pd.DataFrame, file_path: str) -> str:
    os.makedirs(PLOT_DIR, exist_ok=True)
    plot_path = os.path.join(PLOT_DIR, f"{_safe_artifact_name(file_path)}_numeric_histograms.png")
    column_count = numeric_df.shape[1]
    cols = min(3, column_count)
    rows = int(np.ceil(column_count / cols))

    fig, axes = plt.subplots(rows, cols, figsize=(cols * 4.2, rows * 3.2))
    axes_array = np.array(axes).reshape(-1)

    for axis, column in zip(axes_array, numeric_df.columns):
        axis.hist(numeric_df[column].dropna(), bins=min(30, max(5, len(numeric_df) // 2)), color="#2563eb", alpha=0.78)
        axis.set_title(str(column))
        axis.set_xlabel("Value")
        axis.set_ylabel("Count")

    for axis in axes_array[len(numeric_df.columns):]:
        axis.set_visible(False)

    fig.suptitle("Numeric column histograms", y=1.01)
    fig.tight_layout()
    fig.savefig(plot_path, dpi=140, bbox_inches="tight")
    plt.close(fig)

    return plot_path


def _plot_numeric_boxplot(numeric_df: pd.DataFrame, file_path: str) -> str:
    os.makedirs(PLOT_DIR, exist_ok=True)
    plot_path = os.path.join(PLOT_DIR, f"{_safe_artifact_name(file_path)}_numeric_boxplot.png")
    columns = list(numeric_df.columns)
    figure_width = min(18, max(9, len(columns) * 0.42))
    figure_height = min(10, max(6, len(columns) * 0.18))

    fig, axis = plt.subplots(figsize=(figure_width, figure_height))
    axis.boxplot(
        [numeric_df[column].dropna().to_numpy() for column in columns],
        tick_labels=[str(column) for column in columns],
        showfliers=True,
        vert=False,
    )
    axis.set_xlabel("Value")
    axis.set_ylabel("Numeric column")
    axis.set_title("Numeric column boxplot")
    axis.tick_params(axis="y", labelsize=7)
    fig.tight_layout()
    fig.savefig(plot_path, dpi=150, bbox_inches="tight")
    plt.close(fig)

    return plot_path


def _plot_column_means_barplot(numeric_df: pd.DataFrame, file_path: str) -> str:
    os.makedirs(PLOT_DIR, exist_ok=True)
    plot_path = os.path.join(PLOT_DIR, f"{_safe_artifact_name(file_path)}_column_means_barplot.png")
    means = numeric_df.mean(numeric_only=True).sort_values(ascending=False)
    figure_width = min(18, max(9, len(means) * 0.42))
    figure_height = min(10, max(6, len(means) * 0.18))

    fig, axis = plt.subplots(figsize=(figure_width, figure_height))
    axis.barh([str(column) for column in means.index], means.values, color="#0f8a52")
    axis.invert_yaxis()
    axis.set_xlabel("Mean value")
    axis.set_ylabel("Numeric column")
    axis.set_title("Column means bar plot")
    axis.tick_params(axis="y", labelsize=7)
    fig.tight_layout()
    fig.savefig(plot_path, dpi=150, bbox_inches="tight")
    plt.close(fig)

    return plot_path


def _create_plots(
    preprocessed: PreprocessedCsv,
    errors: np.ndarray,
    threshold: float,
    anomalies: list[int],
    file_path: str,
) -> dict[str, str]:
    plots = {
        "error_distribution": _plot_error_distribution(errors, threshold, file_path),
        "error_by_row": _plot_error_by_row(errors, threshold, anomalies, file_path),
        "top_scores": _plot_top_scores(errors, file_path),
        "numeric_histograms": _plot_numeric_histograms(preprocessed.numeric_df, file_path),
        "numeric_boxplot": _plot_numeric_boxplot(preprocessed.numeric_df, file_path),
        "column_means_barplot": _plot_column_means_barplot(preprocessed.numeric_df, file_path),
    }
    heatmap_path = _plot_correlation_heatmap(preprocessed.numeric_df, file_path)
    if heatmap_path:
        plots["correlation_heatmap"] = heatmap_path
    return plots


def _risk_score(errors: np.ndarray, threshold: float, anomalies: list[int]) -> dict[str, Any]:
    if len(errors) == 0:
        return {"score": 0, "level": "Low", "anomaly_rate": 0.0, "max_score_ratio": 0.0}

    anomaly_rate = len(anomalies) / len(errors)
    max_score_ratio = float(errors.max() / threshold) if threshold > 0 else 0.0
    consensus_weight = 40 if anomalies else 0
    raw_score = consensus_weight + (anomaly_rate * 30) + (min(max_score_ratio, 2.0) / 2.0 * 30)
    score = int(round(min(100.0, raw_score)))

    if score >= 70:
        level = "High"
    elif score >= 35:
        level = "Medium"
    else:
        level = "Low"

    return {
        "score": score,
        "level": level,
        "anomaly_rate": float(anomaly_rate),
        "max_score_ratio": float(max_score_ratio),
    }


def _anomaly_details(preprocessed: PreprocessedCsv, errors: np.ndarray, anomalies: list[int]) -> list[dict[str, Any]]:
    details: list[dict[str, Any]] = []
    means = preprocessed.numeric_df.mean(numeric_only=True)
    stds = preprocessed.numeric_df.std(numeric_only=True, ddof=0).replace(0, np.nan)

    for row_idx in anomalies:
        row = preprocessed.numeric_df.iloc[row_idx]
        z_scores = ((row - means) / stds).replace([np.inf, -np.inf], np.nan).abs().fillna(0.0)
        top_columns = z_scores.sort_values(ascending=False).head(3)
        details.append(
            {
                "row_index": int(row_idx),
                "anomaly_score": float(errors[row_idx]),
                "top_deviating_columns": [
                    {
                        "column": str(column),
                        "value": float(row[column]),
                        "mean": float(means[column]),
                        "z_score": float(z_score),
                    }
                    for column, z_score in top_columns.items()
                ],
            }
        )
    return details


def _summary(preprocessed: PreprocessedCsv, threshold: float, losses: list[float]) -> dict[str, Any]:
    stats = preprocessed.numeric_df.describe().round(4).replace({np.nan: None}).to_dict()
    missing_values = preprocessed.raw_df.isna().sum().to_dict()
    non_numeric_columns = [
        column for column in preprocessed.raw_df.columns if column not in preprocessed.columns
    ]
    return {
        "rows": int(preprocessed.raw_df.shape[0]),
        "columns": int(preprocessed.raw_df.shape[1]),
        "numeric_columns": preprocessed.columns,
        "numeric_column_count": len(preprocessed.columns),
        "non_numeric_columns": non_numeric_columns,
        "missing_values": {str(key): int(value) for key, value in missing_values.items()},
        "threshold": float(threshold),
        "training_epochs": DEFAULT_EPOCHS,
        "final_training_loss": float(losses[-1]) if losses else None,
        "basic_stats": stats,
    }


def analyze_csv_dl(file_path: str) -> dict[str, Any]:
    """
    Analyze a CSV with a PyTorch autoencoder and Isolation Forest baseline.

    Returns a JSON-serializable dictionary containing summary stats, consensus
    anomaly indices, and per-row autoencoder reconstruction scores.
    """
    preprocessed = _load_and_preprocess_csv(file_path)
    model, losses = _train_autoencoder(preprocessed.features)
    errors = _reconstruction_errors(model, preprocessed.features)
    threshold = float(errors.mean() + 2 * errors.std())

    autoencoder_anomalies = {idx for idx, error in enumerate(errors) if error > threshold}
    isolation_anomalies = _isolation_forest_anomalies(preprocessed.features)
    consensus_anomalies = sorted(autoencoder_anomalies & isolation_anomalies)

    model_path = _save_model(model, file_path, preprocessed.columns, losses)
    plots = _create_plots(preprocessed, errors, threshold, consensus_anomalies, file_path)

    return {
        "summary": _summary(preprocessed, threshold, losses),
        "risk_score": _risk_score(errors, threshold, consensus_anomalies),
        "anomalies": consensus_anomalies,
        "anomaly_details": _anomaly_details(preprocessed, errors, consensus_anomalies),
        "anomaly_scores": [float(score) for score in errors],
        "autoencoder_anomalies": sorted(autoencoder_anomalies),
        "isolation_forest_anomalies": sorted(isolation_anomalies),
        "model_path": model_path,
        "plot_path": plots["error_distribution"],
        "plot_paths": plots,
    }


def _format_csv_analysis_report(file_path: str, analysis: dict[str, Any]) -> str:
    raw_df = pd.read_csv(file_path)
    numeric_df = raw_df.select_dtypes(include=[np.number]).copy()
    summary = analysis.get("summary", {})
    risk = analysis.get("risk_score", {})
    anomalies = analysis.get("anomalies", [])
    scores = analysis.get("anomaly_scores", [])
    details = analysis.get("anomaly_details", [])

    lines = [
        f"CSV anomaly report for {os.path.basename(file_path)}",
        "",
        "Purpose: This report is generated by the PyTorch autoencoder CSV anomaly detector.",
        "Use it as searchable context for questions that connect transaction anomalies to smart contract code.",
        "",
        f"Rows analyzed: {summary.get('rows')}",
        f"Total columns: {summary.get('columns')}",
        f"Numeric columns: {', '.join(summary.get('numeric_columns', []))}",
        f"Non-numeric columns ignored by model: {', '.join(summary.get('non_numeric_columns', [])) or 'None'}",
        f"Missing values by column: {summary.get('missing_values', {})}",
        f"Autoencoder threshold: {summary.get('threshold')}",
        f"Final training loss: {summary.get('final_training_loss')}",
        f"Risk score: {risk.get('score')}/100",
        f"Risk level: {risk.get('level')}",
        f"Anomaly rate: {risk.get('anomaly_rate')}",
        f"Consensus anomaly row indices: {anomalies}",
        f"Autoencoder anomaly row indices: {analysis.get('autoencoder_anomalies', [])}",
        f"Isolation Forest anomaly row indices: {analysis.get('isolation_forest_anomalies', [])}",
        "",
        "Anomalous row details:",
    ]

    if anomalies:
        for row_idx in anomalies:
            row_values = numeric_df.iloc[row_idx].round(6).to_dict()
            score = scores[row_idx] if row_idx < len(scores) else None
            lines.append(f"- Row {row_idx}: anomaly_score={score}; numeric_values={row_values}")
        lines.append("")
        lines.append("Top mathematical deviations by anomalous row:")
        for detail in details:
            deviations = "; ".join(
                (
                    f"{item['column']} value={item['value']} "
                    f"mean={item['mean']} abs_z={item['z_score']:.3f}"
                )
                for item in detail.get("top_deviating_columns", [])
            )
            lines.append(f"- Row {detail.get('row_index')}: {deviations}")
    else:
        lines.append("- No consensus anomalies were found by both models.")

    lines.extend(
        [
            "",
            "Column averages:",
            str(numeric_df.mean(numeric_only=True).round(6).to_dict()),
            "",
            "Column standard deviations:",
            str(numeric_df.std(numeric_only=True, ddof=0).round(6).to_dict()),
            "",
            "Generated plot files:",
            str(analysis.get("plot_paths", {})),
        ]
    )

    return "\n".join(lines) + "\n"


def save_csv_anomaly_report(file_path: str, analysis: dict[str, Any], output_dir: str = "workspace_uploads") -> str:
    """Write a searchable text report that can be indexed for cross-file RAG."""
    os.makedirs(output_dir, exist_ok=True)
    report_path = os.path.join(output_dir, f"{_safe_artifact_name(file_path)}_anomaly_report.txt")

    with open(report_path, "w", encoding="utf-8") as report_file:
        report_file.write(_format_csv_analysis_report(file_path, analysis))

    return report_path


def explain_anomalies_with_llama(file_path: str, analysis: dict[str, Any], max_rows: int = 5) -> str:
    """
    Ask Llama 3.1 to explain why the highest-confidence anomalous rows look unusual.
    """
    if not os.getenv("GROQ_API_KEY"):
        return "Llama explanation skipped because GROQ_API_KEY is not configured."

    details = analysis.get("anomaly_details", [])[:max_rows]
    if not details:
        return "No consensus anomalies were found by both the autoencoder and Isolation Forest."

    compact_rows = [
        {
            "row_index": item.get("row_index"),
            "anomaly_score": round(float(item.get("anomaly_score", 0.0)), 6),
            "top_deviations": [
                {
                    "column": deviation.get("column"),
                    "value": round(float(deviation.get("value", 0.0)), 6),
                    "mean": round(float(deviation.get("mean", 0.0)), 6),
                    "absolute_z_score": round(float(deviation.get("z_score", 0.0)), 2),
                }
                for deviation in item.get("top_deviating_columns", [])[:3]
            ],
        }
        for item in details
    ]

    llm = ChatGroq(
        groq_api_key=os.getenv("GROQ_API_KEY"),
        model_name="llama-3.1-8b-instant",
        temperature=0,
        max_tokens=1200,
        timeout=8,
        max_retries=1,
    )
    prompt = ChatPromptTemplate.from_template(
        """
You are a senior data analyst. Explain why these CSV rows are mathematically suspicious.
Use only the supplied anomaly score and top deviations. Do not invent business meaning.
For each row, write exactly two concise bullets: one for the strongest numeric reason and one for what to review next.

ANOMALOUS ROWS:
{rows}

AUTOENCODER THRESHOLD:
{threshold}

Return short bullets by row index.
"""
    )
    chain = prompt | llm | StrOutputParser()
    return chain.invoke(
        {
            "rows": json.dumps(compact_rows, default=str),
            "threshold": analysis.get("summary", {}).get("threshold"),
        }
    )


def format_local_anomaly_explanations(analysis: dict[str, Any], max_rows: int = 25) -> str:
    """Create deterministic explanations so every anomaly row has readable text."""
    details = analysis.get("anomaly_details", [])[:max_rows]
    if not details:
        return "No consensus anomalies were found by both the autoencoder and Isolation Forest."

    lines = ["### Mathematical anomaly explanations"]
    for detail in details:
        lines.append(f"- **Row {detail['row_index']}**: anomaly score `{detail['anomaly_score']:.6f}`.")
        deviations = detail.get("top_deviating_columns", [])
        if not deviations:
            lines.append("  - No strong single-column deviation was identified.")
            continue
        for item in deviations:
            lines.append(
                "  - "
                f"`{item['column']}` is `{item['value']:.6g}` versus mean "
                f"`{item['mean']:.6g}` (absolute z-score `{item['z_score']:.2f}`)."
            )
    if len(analysis.get("anomaly_details", [])) > max_rows:
        lines.append(f"- Showing first {max_rows} anomalous rows.")
    return "\n".join(lines)


def save_analysis_report_to_workspace(
    file_path: str,
    analysis: dict[str, Any],
    workspace_dir: str = "workspace_uploads",
) -> str:
    """
    Save the CSV analysis report as a workspace text file so the AI can retrieve it.

    The returned .txt path can be passed to process_document() for indexing.
    """
    return save_csv_anomaly_report(file_path, analysis, output_dir=workspace_dir)
