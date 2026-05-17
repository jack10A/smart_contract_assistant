# =========================
# 1. Install / Imports
# =========================

import os
import json
import shutil
import zipfile
from pathlib import Path

import kagglehub
import torch
import torch.nn as nn
from torch.utils.data import DataLoader
from torchvision import datasets, transforms, models

from sklearn.metrics import classification_report, confusion_matrix
import numpy as np


# =========================
# 2. Download Dataset
# =========================

path = kagglehub.dataset_download("saurabhshahane/phishiris")
print("Path to dataset files:", path)

DATA_ROOT = Path(path)
print("Files:", list(DATA_ROOT.iterdir()))


# =========================
# 3. Locate train / val folders
# =========================

def find_split_dirs(root):
    candidates = list(root.rglob("train"))
    train_dir = candidates[0] if candidates else None

    val_candidates = list(root.rglob("val"))
    test_candidates = list(root.rglob("test"))

    val_dir = val_candidates[0] if val_candidates else (test_candidates[0] if test_candidates else None)
    return train_dir, val_dir

train_dir, val_dir = find_split_dirs(DATA_ROOT)

print("Train dir:", train_dir)
print("Val dir:", val_dir)

assert train_dir is not None, "Could not find train folder"
assert val_dir is not None, "Could not find val/test folder"


# =========================
# 4. Build Binary Dataset
# =========================

BINARY_ROOT = Path("/kaggle/working/phishiris_binary")

if BINARY_ROOT.exists():
    shutil.rmtree(BINARY_ROOT)

for split_name, source_dir in [("train", train_dir), ("val", val_dir)]:
    for class_folder in source_dir.iterdir():
        if not class_folder.is_dir():
            continue

        binary_label = "legitimate_or_other" if class_folder.name.lower() == "other" else "phishing_page"
        target_dir = BINARY_ROOT / split_name / binary_label
        target_dir.mkdir(parents=True, exist_ok=True)

        for img_path in class_folder.glob("*"):
            if img_path.suffix.lower() in [".png", ".jpg", ".jpeg", ".webp", ".bmp"]:
                shutil.copy(img_path, target_dir / f"{class_folder.name}_{img_path.name}")

print("Binary dataset created at:", BINARY_ROOT)

for split in ["train", "val"]:
    for cls in ["phishing_page", "legitimate_or_other"]:
        folder = BINARY_ROOT / split / cls
        print(split, cls, len(list(folder.glob("*"))))


# =========================
# 5. Transforms / DataLoaders
# =========================

IMG_SIZE = 224
BATCH_SIZE = 32

train_tfms = transforms.Compose([
    transforms.Resize((IMG_SIZE, IMG_SIZE)),
    transforms.RandomHorizontalFlip(p=0.2),
    transforms.ColorJitter(brightness=0.15, contrast=0.15),
    transforms.ToTensor(),
    transforms.Normalize(
        mean=[0.485, 0.456, 0.406],
        std=[0.229, 0.224, 0.225],
    ),
])

val_tfms = transforms.Compose([
    transforms.Resize((IMG_SIZE, IMG_SIZE)),
    transforms.ToTensor(),
    transforms.Normalize(
        mean=[0.485, 0.456, 0.406],
        std=[0.229, 0.224, 0.225],
    ),
])

train_ds = datasets.ImageFolder(BINARY_ROOT / "train", transform=train_tfms)
val_ds = datasets.ImageFolder(BINARY_ROOT / "val", transform=val_tfms)

train_loader = DataLoader(train_ds, batch_size=BATCH_SIZE, shuffle=True, num_workers=2)
val_loader = DataLoader(val_ds, batch_size=BATCH_SIZE, shuffle=False, num_workers=2)

print("Classes:", train_ds.classes)
print("class_to_idx:", train_ds.class_to_idx)


# =========================
# 6. Model
# =========================

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print("Device:", device)

model = models.mobilenet_v3_small(weights=models.MobileNet_V3_Small_Weights.DEFAULT)

num_features = model.classifier[-1].in_features
model.classifier[-1] = nn.Linear(num_features, len(train_ds.classes))

model = model.to(device)


# =========================
# 7. Loss / Optimizer
# =========================

criterion = nn.CrossEntropyLoss()
optimizer = torch.optim.AdamW(model.parameters(), lr=2e-4, weight_decay=1e-4)

EPOCHS = 8


# =========================
# 8. Train / Eval Helpers
# =========================

def train_one_epoch(model, loader):
    model.train()
    total_loss = 0
    correct = 0
    total = 0

    for images, labels in loader:
        images = images.to(device)
        labels = labels.to(device)

        optimizer.zero_grad()

        outputs = model(images)
        loss = criterion(outputs, labels)

        loss.backward()
        optimizer.step()

        total_loss += loss.item() * images.size(0)

        preds = outputs.argmax(dim=1)
        correct += (preds == labels).sum().item()
        total += labels.size(0)

    return total_loss / total, correct / total


@torch.no_grad()
def evaluate(model, loader):
    model.eval()
    total_loss = 0
    correct = 0
    total = 0

    all_preds = []
    all_labels = []

    for images, labels in loader:
        images = images.to(device)
        labels = labels.to(device)

        outputs = model(images)
        loss = criterion(outputs, labels)

        total_loss += loss.item() * images.size(0)

        preds = outputs.argmax(dim=1)

        correct += (preds == labels).sum().item()
        total += labels.size(0)

        all_preds.extend(preds.cpu().numpy())
        all_labels.extend(labels.cpu().numpy())

    return total_loss / total, correct / total, np.array(all_preds), np.array(all_labels)


# =========================
# 9. Training Loop
# =========================

best_acc = 0.0
SAVE_DIR = Path("/kaggle/working/image_classifier_model")
SAVE_DIR.mkdir(parents=True, exist_ok=True)

best_model_path = SAVE_DIR / "model.pt"

for epoch in range(1, EPOCHS + 1):
    train_loss, train_acc = train_one_epoch(model, train_loader)
    val_loss, val_acc, preds, labels = evaluate(model, val_loader)

    print(
        f"Epoch {epoch}/{EPOCHS} | "
        f"train_loss={train_loss:.4f} train_acc={train_acc:.4f} | "
        f"val_loss={val_loss:.4f} val_acc={val_acc:.4f}"
    )

    if val_acc > best_acc:
        best_acc = val_acc
        torch.save(model.state_dict(), best_model_path)
        print("Saved best model:", best_model_path)


# =========================
# 10. Final Evaluation Metrics
# =========================

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
)
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd

model.load_state_dict(torch.load(best_model_path, map_location=device))

val_loss, val_acc, preds, labels = evaluate(model, val_loader)

accuracy = accuracy_score(labels, preds)
precision_macro = precision_score(labels, preds, average="macro", zero_division=0)
recall_macro = recall_score(labels, preds, average="macro", zero_division=0)
f1_macro = f1_score(labels, preds, average="macro", zero_division=0)

precision_weighted = precision_score(labels, preds, average="weighted", zero_division=0)
recall_weighted = recall_score(labels, preds, average="weighted", zero_division=0)
f1_weighted = f1_score(labels, preds, average="weighted", zero_division=0)

cm = confusion_matrix(labels, preds)

print("========== FINAL METRICS ==========")
print(f"Accuracy:           {accuracy:.4f}")
print(f"Precision Macro:    {precision_macro:.4f}")
print(f"Recall Macro:       {recall_macro:.4f}")
print(f"F1 Macro:           {f1_macro:.4f}")
print(f"Precision Weighted: {precision_weighted:.4f}")
print(f"Recall Weighted:    {recall_weighted:.4f}")
print(f"F1 Weighted:        {f1_weighted:.4f}")

print("\n========== CONFUSION MATRIX ==========")
print(cm)

print("\n========== CLASSIFICATION REPORT ==========")
report_text = classification_report(
    labels,
    preds,
    target_names=val_ds.classes,
    zero_division=0,
)
print(report_text)
# =========================
# 10.1 Save Metrics
# =========================

metrics = {
    "accuracy": float(accuracy),
    "precision_macro": float(precision_macro),
    "recall_macro": float(recall_macro),
    "f1_macro": float(f1_macro),
    "precision_weighted": float(precision_weighted),
    "recall_weighted": float(recall_weighted),
    "f1_weighted": float(f1_weighted),
    "val_loss": float(val_loss),
    "val_acc": float(val_acc),
}

with open(SAVE_DIR / "metrics.json", "w") as f:
    json.dump(metrics, f, indent=2)

with open(SAVE_DIR / "classification_report.txt", "w") as f:
    f.write(report_text)

cm_df = pd.DataFrame(
    cm,
    index=val_ds.classes,
    columns=val_ds.classes,
)

cm_df.to_csv(SAVE_DIR / "confusion_matrix.csv")

plt.figure(figsize=(7, 6))
sns.heatmap(
    cm_df,
    annot=True,
    fmt="d",
    cmap="Blues",
    cbar=False,
)
plt.title("Confusion Matrix")
plt.ylabel("True Label")
plt.xlabel("Predicted Label")
plt.tight_layout()
plt.savefig(SAVE_DIR / "confusion_matrix.png", dpi=160)
plt.show()

print("Saved metrics files:")
print(SAVE_DIR / "metrics.json")
print(SAVE_DIR / "classification_report.txt")
print(SAVE_DIR / "confusion_matrix.csv")
print(SAVE_DIR / "confusion_matrix.png")



# =========================
# 11. Save Labels + Config
# =========================

labels_json = {
    "classes": train_ds.classes,
    "class_to_idx": train_ds.class_to_idx,
    "idx_to_class": {v: k for k, v in train_ds.class_to_idx.items()},
}

with open(SAVE_DIR / "labels.json", "w") as f:
    json.dump(labels_json, f, indent=2)

config = {
    "model_name": "mobilenet_v3_small",
    "image_size": IMG_SIZE,
    "num_classes": len(train_ds.classes),
    "normalization_mean": [0.485, 0.456, 0.406],
    "normalization_std": [0.229, 0.224, 0.225],
    "task": "binary_phishing_screenshot_classification",
}

with open(SAVE_DIR / "config.json", "w") as f:
    json.dump(config, f, indent=2)

print("Saved model artifacts to:", SAVE_DIR)
print(list(SAVE_DIR.iterdir()))


# =========================
# 12. Zip Model Folder
# =========================

ZIP_PATH = Path("/kaggle/working/image_classifier_model.zip")

if ZIP_PATH.exists():
    ZIP_PATH.unlink()

with zipfile.ZipFile(ZIP_PATH, "w", zipfile.ZIP_DEFLATED) as zipf:
    for file in SAVE_DIR.iterdir():
        zipf.write(file, arcname=file.name)

print("Created zip:", ZIP_PATH)
print("Files inside zip:")
with zipfile.ZipFile(ZIP_PATH, "r") as zipf:
    print(zipf.namelist())

