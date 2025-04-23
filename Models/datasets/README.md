# Датасеты для ThreatDetector

## Доступные датасеты

Для работы с ThreatDetector требуются следующие наборы данных:

1. **malware.csv** (48MB) - Набор данных для обучения модели обнаружения вредоносных PE-файлов
2. **url_features.csv** (156MB) - Набор данных для обучения модели обнаружения фишинговых URL

## Загрузка датасетов

Из-за большого размера, эти файлы не хранятся непосредственно в репозитории. Вы можете получить их следующими способами:

### PE Malware Dataset

Для датасета malware.csv вы можете:

1. Загрузить из Kaggle: [Malware PE Files Dataset](https://www.kaggle.com/datasets/example/malware-pe-files)
2. Или воспользоваться прямой ссылкой: [Google Drive](https://drive.google.com/file/d/...)

### URL Phishing Dataset

URL-датасет доступен через Hugging Face:

```python
from datasets import load_dataset

# Загрузка датасета
dataset = load_dataset("username/url-phishing-dataset")
```

## Использование в проекте

После загрузки поместите файлы CSV в эту директорию (Models/datasets/).

Jupyter ноутбуки в директории Models/notebooks/ настроены на работу с этими датасетами.

## Структура датасетов

### malware.csv

```
sha256,machine,size_of_optional_header,characteristics,major_linker_version,...
abc123...,332,224,8231,9,...
```

### url_features.csv

```
url,has_ip,url_length,domain_length,...,label
example.com,0,15,11,...,0
phishing-example.net,0,31,19,...,1
```
