# ============================================================
# FINAL CORRECT CodeBERT Training
# Dataset : SC_4label.csv only
# Classes : RE, OF, TP, DE (4 real verified labels)
# Target  : F1 > 0.75 | Run on Kaggle T4 x2 GPU
# ============================================================

# ============================================================
# 1. INSTALL & IMPORTS
# ============================================================
import subprocess
subprocess.run(["pip", "install", "transformers", "datasets", "accelerate",
                "scikit-learn", "matplotlib", "seaborn", "-q"])

import os, re, shutil
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import matplotlib.pyplot as plt
import seaborn as sns

from datasets import Dataset
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    TrainingArguments,
    Trainer,
    set_seed,
    EarlyStoppingCallback
)
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    confusion_matrix,
    classification_report
)
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_class_weight

# ============================================================
# 2. CONFIGURATION
# ============================================================
SEED       = 42
MODEL_NAME = "microsoft/codebert-base"
MAX_LEN    = 512
STRIDE     = 64
OUTPUT_DIR = "./results"
FINAL_DIR  = "./final_model"

set_seed(SEED)

# ============================================================
# 3. FIND FILE
# ============================================================
def find_file(name):
    for root, _, files in os.walk('/'):
        if name in files:
            return os.path.join(root, name)
    return name

# ============================================================
# 4. LOAD DATA
# ============================================================
df = pd.read_csv(find_file("SC_4label.csv"))
df = df.dropna(subset=["code", "label"])
print(f"Total samples: {len(df)}")

# ============================================================
# 5. EXTRACT CORRECT LABELS FROM FOLDER PATH
#    e.g. '/content/.../reentrancy (RE)/' → 'RE'
#    This is the KEY fix — never use label_encoded across files
# ============================================================
def extract_label(path):
    match = re.search(r'\((\w+)\)', str(path))
    return match.group(1) if match else None

df["clean_label"] = df["label"].apply(extract_label)
df = df.dropna(subset=["clean_label"])

print("\nLabel distribution:")
print(df["clean_label"].value_counts())

# ============================================================
# 6. ENCODE LABELS — full readable names
# ============================================================
label_names = {
    "RE": "Reentrancy",
    "OF": "Integer Overflow",
    "TP": "Timestamp Dependency",
    "DE": "Dangerous Delegatecall"
}

unique_labels = sorted(df["clean_label"].unique())
NUM_LABELS    = len(unique_labels)
label2id      = {l: i for i, l in enumerate(unique_labels)}
id2label      = {i: label_names.get(l, l) for i, l in enumerate(unique_labels)}

df["label"] = df["clean_label"].map(label2id).astype(int)

print(f"\nNum Labels: {NUM_LABELS}")
print("Label mapping:")
for k, v in id2label.items():
    print(f"  {k} → {v}")

# ============================================================
# 7. CLEAN SOLIDITY CODE
# ============================================================
def clean_solidity(code):
    code = re.sub(r'//.*',           '', str(code))
    code = re.sub(r'/\*[\s\S]*?\*/', '', code)
    code = re.sub(r'\s+',            ' ', code)
    return code.strip()

df["text"] = df["code"].apply(clean_solidity)
df = df[df["text"].str.len() > 50].reset_index(drop=True)
print(f"\nAfter cleaning: {len(df)} contracts")

# ============================================================
# 8. STRATIFIED 3-WAY SPLIT  (70 / 15 / 15)
# ============================================================
train_df, temp_df = train_test_split(
    df, test_size=0.30, random_state=SEED, stratify=df["label"]
)
val_df, test_df = train_test_split(
    temp_df, test_size=0.50, random_state=SEED, stratify=temp_df["label"]
)

print(f"\nTrain: {len(train_df)} | Val: {len(val_df)} | Test: {len(test_df)}")

# ============================================================
# 9. SLIDING WINDOW TOKENIZATION
# ============================================================
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

def sliding_window_tokenize(texts, labels, desc=""):
    input_ids_all, masks_all, labels_all = [], [], []
    step = MAX_LEN - 2 - STRIDE

    for text, label in zip(list(texts), list(labels)):
        ids = tokenizer(
            text, add_special_tokens=False, truncation=False
        )["input_ids"]

        # Short contract — single chunk, no sliding needed
        if len(ids) <= MAX_LEN - 2:
            chunk = [tokenizer.cls_token_id] + ids + [tokenizer.sep_token_id]
            p_len = MAX_LEN - len(chunk)
            input_ids_all.append(chunk + [tokenizer.pad_token_id] * p_len)
            masks_all.append([1] * len(chunk) + [0] * p_len)
            labels_all.append(int(label))
            continue

        # Long contract — sliding window
        for i in range(0, len(ids), step):
            piece = ids[i : i + MAX_LEN - 2]
            if len(piece) < 32:
                continue
            chunk = [tokenizer.cls_token_id] + piece + [tokenizer.sep_token_id]
            p_len = MAX_LEN - len(chunk)
            input_ids_all.append(chunk + [tokenizer.pad_token_id] * p_len)
            masks_all.append([1] * len(chunk) + [0] * p_len)
            labels_all.append(int(label))

    print(f"{desc}: {len(labels_all)} chunks from {len(labels)} contracts")
    return Dataset.from_dict({
        "input_ids":      input_ids_all,
        "attention_mask": masks_all,
        "labels":         labels_all
    })

train_ds = sliding_window_tokenize(train_df["text"], train_df["label"], "Train")
val_ds   = sliding_window_tokenize(val_df["text"],   val_df["label"],   "Val")
test_ds  = sliding_window_tokenize(test_df["text"],  test_df["label"],  "Test")

# ============================================================
# 10. CLASS WEIGHTS — handle imbalance (DE only has 97 samples)
# ============================================================
train_labels_np = np.array(train_ds["labels"])
class_weights   = compute_class_weight(
    "balanced",
    classes=np.unique(train_labels_np),
    y=train_labels_np
)
weights = torch.tensor(class_weights, dtype=torch.float)

print("\nClass weights:")
for i, w in enumerate(class_weights):
    print(f"  {id2label[i]}: {w:.3f}")

# ============================================================
# 11. CUSTOM TRAINER — Weighted Cross-Entropy + Label Smoothing
# ============================================================
class WeightedTrainer(Trainer):
    def compute_loss(self, model, inputs, return_outputs=False, **kwargs):
        labels  = inputs.pop("labels")
        outputs = model(**inputs)
        loss_fct = nn.CrossEntropyLoss(
            weight=weights.to(outputs.logits.device),
            label_smoothing=0.1
        )
        loss = loss_fct(outputs.logits, labels.long())
        return (loss, outputs) if return_outputs else loss

# ============================================================
# 12. MODEL — full fine-tuning, mild dropout
# ============================================================
model = AutoModelForSequenceClassification.from_pretrained(
    MODEL_NAME,
    num_labels=NUM_LABELS,
    id2label=id2label,
    label2id={v: k for k, v in id2label.items()},
    hidden_dropout_prob=0.2,
    attention_probs_dropout_prob=0.2
)

for param in model.parameters():
    param.requires_grad = True

trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
print(f"\nTrainable params: {trainable:,}")

# ============================================================
# 13. TRAINING ARGUMENTS
# ============================================================
training_args = TrainingArguments(
    output_dir=OUTPUT_DIR,
    num_train_epochs=15,
    per_device_train_batch_size=8,
    per_device_eval_batch_size=16,
    gradient_accumulation_steps=4,      # effective batch = 32
    learning_rate=2e-5,
    weight_decay=0.01,
    warmup_ratio=0.1,
    fp16=torch.cuda.is_available(),
    eval_strategy="epoch",
    save_strategy="epoch",
    load_best_model_at_end=True,
    metric_for_best_model="f1",
    greater_is_better=True,
    save_total_limit=2,
    logging_steps=50,
    report_to="none",
    seed=SEED,
    data_seed=SEED,
)

# ============================================================
# 14. METRICS
# ============================================================
def compute_metrics(p):
    preds = np.argmax(p.predictions, axis=-1)
    prec, rec, f1, _ = precision_recall_fscore_support(
        p.label_ids, preds, average="weighted", zero_division=0
    )
    acc = accuracy_score(p.label_ids, preds)
    return {"accuracy": acc, "f1": f1, "precision": prec, "recall": rec}

# ============================================================
# 15. TRAINER
# ============================================================
trainer = WeightedTrainer(
    model=model,
    args=training_args,
    train_dataset=train_ds,
    eval_dataset=val_ds,
    compute_metrics=compute_metrics,
    callbacks=[
        EarlyStoppingCallback(
            early_stopping_patience=4,
            early_stopping_threshold=0.001
        )
    ]
)

# ============================================================
# 16. TRAIN
# ============================================================
print("\n" + "="*50)
print("STARTING TRAINING — 4 Correct Classes")
print("Expected: F1 > 0.75, Accuracy > 80%")
print("="*50)
trainer.train()

# ============================================================
# 17. TEST SET EVALUATION
# ============================================================
print("\n" + "="*50)
print("TEST SET RESULTS")
print("="*50)

test_output = trainer.predict(test_ds)
y_pred      = np.argmax(test_output.predictions, axis=1)
y_true      = test_output.label_ids

print(classification_report(
    y_true, y_pred,
    target_names=list(id2label.values()),
    digits=3
))

# ============================================================
# 18. CONFUSION MATRIX
# ============================================================
cm = confusion_matrix(y_true, y_pred)
plt.figure(figsize=(10, 8))
sns.heatmap(
    cm, annot=True, fmt='d', cmap='Blues',
    xticklabels=list(id2label.values()),
    yticklabels=list(id2label.values())
)
plt.title("Confusion Matrix — 4 Class Test Set", fontsize=14)
plt.ylabel("True Label")
plt.xlabel("Predicted Label")
plt.tight_layout()
plt.savefig("confusion_matrix.png", dpi=150)
plt.show()
print("Confusion matrix saved.")

# ============================================================
# 19. SAVE & EXPORT
# ============================================================
os.makedirs(FINAL_DIR, exist_ok=True)
trainer.save_model(FINAL_DIR)
tokenizer.save_pretrained(FINAL_DIR)

shutil.make_archive("research_model", 'zip', FINAL_DIR)
print("\n✅ DONE! Download research_model.zip from the Output tab.")
