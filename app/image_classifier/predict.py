import json
import os
from typing import Any

import torch
import torch.nn as nn
from PIL import Image
from torchvision import models, transforms


class ImagePhishingClassifier:
    def __init__(self, model_dir: str | None = None):
        if model_dir is None:
            model_dir = os.path.join(os.path.dirname(__file__), "model_weights")

        self.model_dir = model_dir
        self.model_path = os.path.join(model_dir, "model.pt")
        self.labels_path = os.path.join(model_dir, "labels.json")
        self.config_path = os.path.join(model_dir, "config.json")
        self.available = all(os.path.exists(path) for path in [self.model_path, self.labels_path, self.config_path])
        self.model = None
        self.transform = None
        self.idx_to_class: dict[int, str] = {}
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

        if self.available:
            self._load()

    def _load(self) -> None:
        with open(self.labels_path, "r", encoding="utf-8") as labels_file:
            labels = json.load(labels_file)
        with open(self.config_path, "r", encoding="utf-8") as config_file:
            config = json.load(config_file)

        self.idx_to_class = {int(key): value for key, value in labels["idx_to_class"].items()}
        image_size = int(config.get("image_size", 224))
        mean = config.get("normalization_mean", [0.485, 0.456, 0.406])
        std = config.get("normalization_std", [0.229, 0.224, 0.225])

        model = models.mobilenet_v3_small(weights=None)
        in_features = model.classifier[-1].in_features
        model.classifier[-1] = nn.Linear(in_features, len(self.idx_to_class))
        model.load_state_dict(torch.load(self.model_path, map_location=self.device))
        model.to(self.device)
        model.eval()

        self.model = model
        self.transform = transforms.Compose(
            [
                transforms.Resize((image_size, image_size)),
                transforms.ToTensor(),
                transforms.Normalize(mean=mean, std=std),
            ]
        )

    def predict(self, image_path: str) -> dict[str, Any]:
        if not self.available or self.model is None or self.transform is None:
            return {
                "available": False,
                "label": "model_not_available",
                "confidence": 0.0,
                "scores": {},
            }

        with Image.open(image_path) as image:
            tensor = self.transform(image.convert("RGB")).unsqueeze(0).to(self.device)

        with torch.no_grad():
            logits = self.model(tensor)
            probs = torch.softmax(logits, dim=1).squeeze(0).cpu().tolist()

        scores = {self.idx_to_class[idx]: float(score) for idx, score in enumerate(probs)}
        best_idx = int(max(range(len(probs)), key=lambda idx: probs[idx]))
        return {
            "available": True,
            "label": self.idx_to_class[best_idx],
            "confidence": float(probs[best_idx]),
            "scores": scores,
        }


image_phishing_classifier = ImagePhishingClassifier()
