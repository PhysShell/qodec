# Qodec и lossless-сжатие контекста для LLM: общий технический конспект

> **Статус документа.** Авторский программный документ, зафиксирован
> 2026-07-25. Текст ниже — дословный; он не редактируется задним числом.
> Текущее состояние реализации против него — в замороженном milestone
> [`docs/milestones/2026-07-25-lossless-program-e8815f0.md`](milestones/2026-07-25-lossless-program-e8815f0.md).
>
> Карта «раздел → реализация» на дату фиксации:
>
> | Раздел конспекта | Где в репозитории |
> |---|---|
> | §2, §8 — пять gates | G1: roundtrip-тесты крейта · G2: `evals/tokenizer-matrix/` (payload + full-request) · G3/G4: `qodec ab` + `evals/reader-cli/` + interop L2 · G5: **открыт** (Этап F, interop L3) |
> | §4–5, §15, §17 — secondary estimation | ranker `src/rank.rs` (`qodec train`, ordering-only); shadow mode — **открыт** |
> | §6 — tokenizer matrix | `evals/tokenizer-matrix/run.py` + `full_request.py` (8 семейств, chat-template) |
> | §11 — paper baseline | `src/paper.rs` (faithful, расхождения в доке модуля) |
> | §11.3 — model_readability_risk | `qodec risk` (`src/risk.rs`): hazard-флаг, не оракул — семантика уточнена панелями v1–v5 |
> | §12 — ingress compression | `evals/interop/v2/n2/` (per-dialect acceptance records) |
> | §16 — этапы | A ✅ · B ✅ · C ✅ · D ✅ (в основном) · E ✅ (L2 + reader-cli) · F — открыт · G — частично (ranker без shadow mode) |

---

1. Исходная задача

Qodec исследует возможность уменьшать объём текста, передаваемого языковой модели, не теряя исходную информацию.

Базовая схема:

исходный материал P
        ↓
Qodec encoder E
        ↓
закодированное представление E(P)
        ↓
LLM или машинный decoder

Для машинного декодера требуется строгая гарантия:

[
D(E(P)) = P
]

Это означает, что после декодирования восстанавливается исходная последовательность байтов.

Примеры возможных преобразований:

- выделение повторяющихся фрагментов в словарь;
- замена длинных повторов короткими aliases;
- структурное кодирование однородных данных;
- локальные legends;
- профили повторяющихся конструкций;
- композиция нескольких кодеков;
- выбор оптимального разбиения текста через "mosaic";
- специализированные dialect-aware представления результатов инструментов.

Ключевой принцип: Qodec не должен быть просто «умным суммаризатором». Его нормативный путь должен оставаться детерминированным, проверяемым и fail-closed. Архитектура ingress-слоя, trust boundaries, completeness semantics, provenance и per-dialect acceptance подробно зафиксированы в проектном ТЗ.

---

2. Три разных значения слова «без потерь»

Главная опасность всей темы состоит в смешении нескольких разных утверждений.

2.1 Байтовая losslessness

[
D(E(P))=P
]

Это машинно проверяемое свойство кодека.

Проверка:

source
  → encode
  → decode
  → byte comparison

Acceptance criterion:

sha256(source) == sha256(decoded)

Здесь LLM не требуется.

2.2 Отсутствие потерь по количеству токенов

Необходимо доказать, что полное закодированное представление действительно занимает меньше токенов:

[
T(E(P)+L+C)<T(P)
]

где:

- "E(P)" — закодированный payload;
- "L" — legend или dictionary;
- "C" — decoder contract, envelope и прочая обвязка;
- "T" — токенизация целевой модели.

Недостаточно измерять только закодированный payload. Нужно учитывать:

encoded payload
+ dictionary
+ decoder instructions
+ delimiters
+ escaping
+ envelope
+ chat template

Иначе можно заявить 60% экономии на payload, притащив следом словарь размером ещё в 55%.

2.3 Поведенческая эквивалентность для LLM

Даже если:

[
D(E(P))=P
]

из этого не следует:

[
LLM(E(P))=LLM(P)
]

Модель видит разные последовательности токенов:

Вариант A:
    исходный текст P

Вариант B:
    закодированный E(P)
    + словарь
    + инструкция декодирования

Для обычного декодера эти представления эквивалентны. Для нейросети они не обязаны приводить к одинаковым внутренним состояниям и одинаковому поведению.

Поэтому утверждение:

«Qodec является lossless-кодеком»

может быть доказано полностью.

А утверждение:

«Использование Qodec не ухудшает работу Claude Code»

требует отдельного экспериментального доказательства.

---

3. Почему ответы A и B могут различаться

Даже два запуска буквально одинакового запроса к закрытой LLM могут дать разные ответы из-за:

- недетерминированного inference;
- внутреннего batching;
- изменений backend;
- sampling;
- скрытых обновлений модели;
- различий в tool trajectory;
- разного состояния prompt cache.

При Qodec добавляется ещё одна переменная: модель читает другую текстовую форму.

Поэтому целью эксперимента не должно быть получение одинакового текста ответа.

Нужны объективные признаки эквивалентности:

- одинаково правильный извлечённый identifier;
- одинаково найденная ошибка;
- корректный patch;
- прохождение одинаковых тестов;
- совпадение структурированных полей;
- одинаковый конечный task outcome.

---

4. Secondary estimation: от PPMZ и SEE к Qodec

В PPMZ и PAQ использовалась идея вторичной оценки вероятности.

Первичная модель выдаёт прогноз:

[
p=P(y=1\mid x)
]

Вторичная модель корректирует его:

[
p'=f(p,c)
]

где "c" содержит дополнительный контекст и накопленную статистику ошибок.

Пример:

основная модель:
    вероятность успеха = 0.80

вторичная модель:
    в данном классе состояний прогнозы 0.80
    исторически реализуются только в 55% случаев

скорректированная вероятность:
    0.55

В Qodec нет классического арифметического кодера с предсказанием следующего бита, поэтому APM не становится непосредственным механизмом сжатия.

Зато идея хорошо переносится на управление поиском кандидатов.

4.1 Возможное применение

region + codec candidate
        ↓
base ranker
        ↓
secondary estimator
        ↓
скорректированная вероятность выигрыша
        ↓
порядок probes
        ↓
точный token meter
        ↓
детерминированный accept/reject

Secondary estimator может учитывать:

- вид кодека;
- язык и тип содержимого;
- размер региона;
- плотность повторов;
- punctuation density;
- tokenizer/model identity;
- размер legend;
- число aliases;
- недавнюю успешность кодека;
- успешность на соседних регионах;
- тип репозитория или tool dialect.

Например:

base ranker:
    P(tmpl wins) = 0.76

online history:
    последние 20 tmpl probes
    на TypeScript этого репозитория проиграли

secondary estimate:
    P(tmpl wins) = 0.24

Это позволяет:

- раньше запускать перспективные probes;
- не тратить время на заведомо слабые кандидаты;
- адаптироваться к новому репозиторию;
- учитывать особенности конкретного токенизатора;
- реагировать на локальную смену режима данных.

4.2 Что secondary estimator не должен делать

Он не должен заменять точное измерение:

НЕПРАВИЛЬНО:
    estimator сказал, что кодек полезен
    → сразу принять результат

ПРАВИЛЬНО:
    estimator переупорядочил кандидаты
    → точный token meter проверил результат
    → детерминированный выбор

При полном переборе secondary estimation почти не уменьшит итоговый размер результата. Она уменьшит вычислительную стоимость поиска.

Прямое улучшение компрессии появится только при ограниченном probe budget, когда хороший кандидат без ranker мог вообще не быть рассмотрен.

---

5. Замкнутый контур обратной связи

Возникла идея использовать фактическое количество токенов, сообщаемое Claude Code, чтобы корректировать будущие решения Qodec.

Общая логика правильная:

Qodec делает прогноз
        ↓
выбирает стратегию кодирования
        ↓
запрос отправляется модели
        ↓
получаем фактический usage
        ↓
обновляем оценку

Но наивный вариант некорректен.

5.1 Почему общий usage является плохой меткой

Полный запрос Claude Code содержит:

системные инструкции
+ tool definitions
+ CLAUDE.md
+ историю
+ предыдущие ответы
+ tool results
+ MCP context
+ текущий Qodec payload
+ служебную обвязку

Наблюдаемое число:

[
T_{\text{observed}}

T_{\text{system}}
+
T_{\text{tools}}
+
T_{\text{history}}
+
T_{\text{payload}}
+
T_{\text{other}}
]

А Qodec интересует только:

[
T_{\text{payload}}
]

По одному общему числу вклад Qodec-представления восстановить нельзя.

Дополнительную путаницу создают:

- "input_tokens";
- "cache_creation_input_tokens";
- "cache_read_input_tokens";
- output tokens;
- повторные API-вызовы;
- tool loops;
- retries;
- subagents;
- compaction.

Поэтому нельзя обучать:

Qodec fragment estimate
        →
full Claude Code session usage

Это разные величины.

5.2 Корректная калибровка

Нужно сравнивать:

predicted full-request token count
        →
actual full-request token count

или:

predicted isolated payload cost
        →
isolated payload token count

Secondary correction может выглядеть так:

[
\widehat T_{\text{corrected}}

f(\widehat T_{\text{local}}, model, encoding, content)
]

Пример:

локальный прогноз: 4 200
официальный подсчёт: 4 470

наблюдение:
    для данной модели и данного класса кодирования
    локальный счётчик занижает стоимость примерно на 6%

Следующий прогноз:

primary estimate:    4 300
secondary correction: ×1.06
final estimate:      4 558

---

6. Token counting и бесплатный слой экспериментов

Первый уровень тестирования можно выполнять без inference.

Для open-source моделей достаточно скачать:

- tokenizer;
- tokenizer configuration;
- chat template;
- special-token rules.

Затем локально посчитать:

RAW request → chat template → tokenizer → token count
Qodec request → chat template → tokenizer → token count

GPU не требуется. Можно бесплатно прогнать десятки или сотни токенизаторов.

Это позволит построить матрицу:

Модель / tokenizer| RAW| Qodec| Saving
Qwen| …| …| …
Llama| …| …| …
DeepSeek| …| …| …

Но эта матрица доказывает только token reduction, а не сохранение качества.

Для hosted-моделей может использоваться официальный token-count endpoint, если провайдер его предоставляет. Перед внедрением необходимо повторно проверить актуальные тарифы, ограничения и структуру учитываемого запроса.

Рациональная последовательность:

1. бесплатно проверить много tokenizer families;
2. локально проверить небольшие модели;
3. выбрать representative cases;
4. только затем платить за semantic и agentic evaluation.

Такой подход зафиксирован и в отдельной записке по Hugging Face и модельным benchmark.

---

7. Как сделать честный A/B-стенд

«Два абсолютно идентичных запроса» невозможны: если запросы идентичны, в них нет экспериментальной переменной.

Правильная цель:

«Два запроса строятся из одного канонического снимка и различаются только представлением целевого payload.»

7.1 Канонический запрос

request A:
    model       = M
    system      = S
    tools       = T
    history     = H
    task        = Q
    payload     = literal(P)

request B:
    model       = M
    system      = S
    tools       = T
    history     = H
    task        = Q
    payload     = qodec(P)

Должны быть одинаковыми:

- точная модель;
- system prompt;
- tool schemas;
- порядок tools;
- история;
- task;
- repository snapshot;
- permissions;
- budget;
- temperature и доступные параметры;
- состояние окружения;
- максимальное число шагов.

Различается только:

literal(P)

против:

E(P) + legend + decoder contract

7.2 Общий envelope

Можно дать обеим веткам одинаковую обвязку:

<qodec-envelope>
  encoding: literal | mosaic
  dictionary: ...
  payload: ...
</qodec-envelope>

Это позволяет не платить decoder-instruction overhead только в ветке Qodec.

Однако дополнительно должен существовать настоящий naked baseline без envelope, иначе стенд будет честно измерять искусственно раздутую систему.

---

8. Многоуровневая доказательная система

Одной метрики недостаточно.

G1. Byte Reconstruction

Проверяет:

[
D(E(P))=P
]

Метрики:

- byte exact match;
- SHA-256 equality;
- deterministic encoding;
- deterministic decoding.

G2. Net Token Reduction

Проверяет:

[
T_{\text{Qodec full request}}<T_{\text{RAW full request}}
]

Необходимо отдельно публиковать:

raw payload tokens
encoded payload tokens
legend tokens
decoder contract tokens
envelope tokens
full request tokens
net saving

G3. Model Reconstruction

Модель должна восстановить исходный материал или выбранные поля.

Метрики:

- byte exact match;
- line exact match;
- identifier accuracy;
- numeric accuracy;
- structured-field accuracy;
- omission rate.

ROUGE и BLEU могут использоваться как диагностика, но не как acceptance gate для lossless claims.

G4. Task Equivalence

Модель решает объективно проверяемые задачи на RAW и Qodec-входе.

Примеры:

- найти failing test;
- указать точную строку;
- извлечь commit OID;
- определить exit status;
- написать patch;
- ответить на вопрос по коду;
- реконструировать структуру вызовов.

Метрики:

- pass rate;
- paired win/tie/loss;
- confidence interval;
- error class;
- failure preservation.

G5. Agentic Equivalence

Полный агент работает в двух одинаковых изолированных окружениях.

same repository commit
same task
same tools
same model
same budget

A: RAW
B: Qodec

Метрики:

- тесты после выполнения;
- task success;
- число API-вызовов;
- input tokens;
- output tokens;
- cache reads/writes;
- tool calls;
- retries;
- wall-clock latency;
- общая стоимость;
- типы ошибок.

---

9. Frozen replay и live agent

Необходимо два разных режима.

9.1 Frozen replay

Фиксируется конкретный снимок:

system
tools
history
tool results
task
payload

Модель выполняет только следующий шаг.

Преимущества:

- траектория не разъезжается;
- легко сравнивать понимание;
- можно изолировать влияние представления;
- меньше стоимость;
- выше воспроизводимость.

Frozen replay отвечает на вопрос:

«Понимает ли модель Qodec-представление так же хорошо, как RAW?»

9.2 Live agent

Агент реально выполняет инструменты.

После первого шага траектории могут различаться:

A сделал grep, затем read
B сразу открыл нужный файл

Это уже не экспериментальное загрязнение, а часть результата.

Live agent отвечает на вопрос:

«Сохраняется ли итоговая способность агента решать задачу?»

---

10. Что именно можно сжимать в полном контексте

10.1 Tool results, логи и структурированные данные

Наиболее безопасная первая область:

- CI logs;
- test output;
- stack traces;
- JSON;
- таблицы;
- repeated paths;
- repeated diagnostics;
- Git output;
- Docker output;
- accessibility trees.

Для normative path предпочтительны специализированные dialect-aware codecs.

10.2 История разговора

Lossless-кодирование повторов возможно.

Но обычная summarization или compaction уже не являются lossless относительно полной истории.

Нужно различать:

lossless representation

и:

lossy information management

10.3 CLAUDE.md и системные инструкции

Технически сжимать можно, но это высокорисковая область.

Первыми следует оставлять литеральными:

- decoder contract;
- security requirements;
- "MUST" / "MUST NOT";
- acceptance constraints;
- tool-use rules;
- критические operational instructions.

Потенциально сжимаемые части:

- повторяющиеся примеры;
- длинные справочники;
- списки путей;
- historical context;
- boilerplate.

10.4 Tool schemas и MCP definitions

Это структурированная часть API, поэтому её нельзя свободно заменить метатокенами.

Возможные стратегии:

- не загружать неиспользуемые tools;
- tool search;
- динамическая подгрузка;
- сокращение текстовых descriptions;
- дедупликация boilerplate;
- сжатие результатов MCP, а не самих schema;
- caching стабильного префикса.

10.5 Скрытая служебная обвязка

Если провайдер не показывает байты системной обвязки, Qodec не может честно заявить, что сжимает её.

Её влияние можно видеть только косвенно через full-request usage.

Поэтому более чистая исследовательская среда:

прямой Messages API
        ↓
замороженные request fixtures
        ↓
собственный tool loop
        ↓
Claude Code

---

11. Работа arXiv:2604.13066

Работа исследует lossless dictionary encoding для API-моделей без дообучения.

11.1 Основная идея

Алгоритм:

1. разбивает текст на whitespace-separated последовательности;
2. ищет повторяющиеся n-grams;
3. начинает с длинных последовательностей;
4. создаёт aliases вида "<M1>", "<M2>";
5. формирует batch-local dictionary;
6. заменяет непересекающиеся вхождения;
7. передаёт словарь и encoded payload модели;
8. просит модель работать с этим представлением или декодировать его.

Пример:

<M1> = open ticket search customer database
<M2> = click open ticket search customer

Encoded text содержит "<M1>" и "<M2>" вместо повторяющихся фраз.

11.2 Главная ценность работы

Новизна не в самом поиске повторов.

Ценный тезис:

«Современная instruction-following LLM может выучить dictionary substitutions непосредственно из prompt без fine-tuning.»

Для Qodec это подтверждает жизнеспособность базовой гипотезы:

dictionary
+ compressed payload
+ decoder contract
→ API LLM

11.3 Что стоит позаимствовать

Разделение трёх claims

Работа фактически различает:

[
D(E(T))=T
]

[
T(E(T)+D)<T(T)
]

[
LLM(E(T),D)\approx LLM(T)
]

Qodec должен расширить это до пяти gates: bytes, tokens, reconstruction, tasks и agents.

Batch-local dictionaries

Словарь строится только для текущего batch.

Это уменьшает overhead и подтверждает разумность иерархии:

global profile
document-local dictionary
region-local legend

Oracle baseline

Авторы сначала используют готовые шаблоны, затем собственный miner.

Для Qodec полезна аналогичная лестница:

oracle manifest
hand-authored legend
paper baseline
mine-only
profile-only
mosaic/full

Так можно отделить ошибку формата от ошибки поиска шаблонов.

Gross против net compression

Нужно отдельно считать:

- encoded payload;
- dictionary;
- instructions;
- полный request.

Анализ опасных классов данных

Работа показывает проблемы на плотных последовательностях похожих идентификаторов и чисел.

Например:

an16 an17 an18
an26 an27 an28

Для LLM такие записи могут быть визуально и семантически слишком похожи.

Это подсказывает отдельную метрику:

model_readability_risk

Признаки:

- число почти одинаковых dictionary entries;
- numeric density;
- identifier density;
- edit distance между entries;
- visual similarity aliases;
- размер dictionary;
- число aliases в одном участке.

11.4 Что копировать не следует

Whitespace segmentation

Для кода и многих tool outputs этого недостаточно.

Qodec должен учитывать:

- байты;
- punctuation;
- line structure;
- source syntax;
- tokenizer boundaries;
- escaping;
- alias adjacency.

Greedy longest-first selection

Длинный повтор может перекрыть несколько более выгодных коротких повторов.

Qodec "mosaic" с DAG/DP должен сравнивать полную стоимость разбиения.

Упрощённое условие экономии

Нужно измерять точный сериализованный envelope, а не приблизительную стоимость alias.

Фиксированные "<M###>"

Alias должен оптимизироваться одновременно по:

- token cost;
- collision risk;
- readability;
- model confusion;
- escaping;
- соседним символам.

ROUGE/BLEU как lossless evidence

Эти метрики могут считать почти правильным текст, где перепутаны номера узлов, дисков или commit OIDs.

Для Qodec критические поля должны проверяться точно.

Reconstruction как доказательство reasoning equivalence

Способность восстановить текст не доказывает способность одинаково решать downstream-задачи.

11.5 Роль paper baseline в Qodec

Нужно реализовать faithful baseline:

whitespace segmentation
n-grams 2..Lmax
longest-first
frequency order
no overlap
no nested aliases
<M#> aliases
batch-local dictionary
paper-style acceptance rule

Затем сравнить с Qodec:

source/token-aware segmentation
exact serialized token meter
alias search
profile/mine/tmpl codecs
mosaic global optimization
byte-exact verifier
model-readability gates

Работа является сильной related work и хорошим baseline, но не доказательством того, что Qodec автоматически сохраняет agentic performance.

---

12. Qodec Ingress Compression

Отдельный прикладной scope состоит в сжатии результатов инструментов до их первого попадания в контекст.

Архитектура:

Tool execution
    ↓
RAW result
    ↓
Ingress router
    ↓
codec / passthrough
    ↓
verification + provenance
    ↓
model context

Режимы:

Diagnostic heuristic mode

Можно использовать:

- BM25;
- truncation;
- generic JSON collapse;
- OCR;
- LLM summarization;
- DOM cleanup;
- generic tables.

Но такой output не получает semantic-equivalence claim.

Verified codec mode

Требует:

- registered dialect;
- pinned implementation;
- deterministic RAW;
- deterministic encoding;
- semantic verifier;
- adversarial cases;
- independent replay;
- immutable acceptance record;
- completeness semantics.

Категории:

lossless-representation
verified-lossy
heuristic-lossy
passthrough

Если dialect неизвестен или verifier не уверен, должен использоваться RAW passthrough. Полный ingress-contract и Definition of Done уже сформулированы в отдельном документе.

---

13. Какие метрики публиковать

Необходимо избегать одной магической цифры «экономия X%».

Для каждого эксперимента:

LOSSLESS ROUND-TRIP:       PASS / FAIL
RAW PAYLOAD TOKENS:        …
ENCODED PAYLOAD TOKENS:    …
DICTIONARY TOKENS:         …
DECODER CONTRACT TOKENS:   …
FULL REQUEST TOKENS:       …
NET TOKEN SAVING:          …
MODEL RECONSTRUCTION:      …
STRUCTURED FIELD ACCURACY: …
TASK SCORE DELTA:          …
AGENT PASS RATE DELTA:     …
TOTAL SESSION COST DELTA:  …

Формула полной экономии:

[
S_{\text{full}}

\frac{T_{\text{RAW request}}-T_{\text{Qodec request}}}
{T_{\text{RAW request}}}
]

Также нужны:

- confidence intervals;
- paired wins/ties/losses;
- corpus identity;
- exact model identity;
- run date;
- tokenizer identity;
- cache configuration;
- number of repetitions;
- refusal rate;
- passthrough rate;
- failure-preservation rate.

---

14. Основные экспериментальные ошибки

Ошибка 1. Считать только payload

Игнорируются dictionary и instructions.

Ошибка 2. Смешивать byte losslessness и model equivalence

Машинный decoder и LLM — разные системы.

Ошибка 3. Использовать общий session usage как стоимость одного фрагмента

Usage включает tools, history, cache и дополнительные запросы.

Ошибка 4. Сравнивать разные agent trajectories как tokenization benchmark

Для этого нужен frozen replay.

Ошибка 5. Использовать LLM-as-a-judge там, где возможен объективный verifier

Для кода и structured output предпочтительны тесты и точные сравнения.

Ошибка 6. Один запуск считать доказательством

Нужны повторы и парный дизайн.

Ошибка 7. Оптимизировать только входные токены

Более короткий вход может вызвать больше ошибок, повторных чтений и tool calls.

Ошибка 8. Учиться на корреляции без attribution

Рост полного usage не доказывает, что виноват выбранный codec.

Ошибка 9. Не учитывать cache

Короткий запрос может разрушить стабильный cache prefix и оказаться дороже.

Ошибка 10. Называть heuristic summarization lossless compression

Это разные классы систем.

---

15. Два разных оптимизатора

Со временем Qodec может иметь два независимых обучаемых слоя.

15.1 Token calibrator

Цель:

encoding
→ actual input token cost

Это относительно безопасная secondary estimation.

Можно использовать для:

- ranker correction;
- probe ordering;
- tokenizer drift detection;
- model-specific calibration;
- top-K selection перед точным count.

15.2 End-to-end policy learner

Цель:

task + repository + encoding
→ total cost + quality + success

Это уже contextual bandit.

Контекст:

- задача;
- язык;
- repository state;
- модель;
- payload type;
- tool configuration.

Действие:

- literal;
- mine;
- profile;
- tmpl;
- mosaic;
- другой codec.

Награда:

- task success;
- тесты;
- стоимость;
- latency;
- число дополнительных шагов;
- token usage.

Это значительно более рискованный слой. Он не относится к текущему чистому lossless scope и должен появляться только после строгого baseline.

---

16. Рекомендуемый порядок реализации

Этап A. Чистый codec

1. byte-exact encode/decode;
2. deterministic output;
3. provenance;
4. adversarial corpus;
5. fail-closed behavior.

Этап B. Tokenizer matrix

1. open tokenizer families;
2. exact chat templates;
3. RAW/Qodec full-request counting;
4. gross/net accounting;
5. representative corpus.

Этап C. Paper baseline

1. воспроизвести arXiv:2604.13066;
2. oracle dictionary;
3. greedy n-gram miner;
4. batch-local dictionaries;
5. exact token accounting;
6. reconstruction tests.

Этап D. Qodec comparison

1. "mine";
2. "profile";
3. "tmpl";
4. alias optimization;
5. "mosaic";
6. model-readability risk;
7. global versus local dictionaries.

Этап E. Frozen semantic evaluation

1. exact request fixtures;
2. RAW/Qodec paired runs;
3. structured objective tasks;
4. repeated trials;
5. confidence intervals.

Этап F. Live-agent evaluation

1. containerized repositories;
2. fixed commits;
3. identical tasks and tools;
4. task-level verifier;
5. full session cost and behavior.

Этап G. Secondary calibration

Только после появления достаточно чистых наблюдений:

1. shadow mode;
2. prediction logging;
3. no automatic production changes;
4. offline evaluation;
5. gradual candidate reordering;
6. exact token meter remains authoritative.

---

17. Shadow mode

Перед автоматическим изменением политики:

production выбрал A
calibrator рекомендовал B
реально отправили A
записали альтернативный прогноз

После накопления корпуса проверяется:

- насколько часто B был бы меньше;
- насколько велика потенциальная экономия;
- нет ли зависимости от cache state;
- стабильны ли рекомендации между моделями;
- не ухудшается ли model readability;
- не создаёт ли estimator систематических пропусков.

Только затем secondary estimator может менять порядок probes.

---

18. Практический итог

Что уже можно считать твёрдым

1. Qodec может строго доказать byte losslessness.
2. Token savings можно измерять отдельно от model inference.
3. Dictionary overhead должен входить в расчёт.
4. Поведенческая эквивалентность является отдельным claim.
5. Frozen replay и live agent измеряют разные вещи.
6. Secondary estimation подходит для калибровки и управления поиском.
7. Общий Claude Code usage нельзя напрямую приписывать одному Qodec payload.
8. Работа arXiv:2604.13066 подтверждает жизнеспособность in-context dictionary decoding.
9. Её miner пригоден как baseline, но слабее Qodec по архитектуре и строгости.
10. Ingress compression должен быть dialect-aware, fail-closed и разделять diagnostic и normative paths.

Что пока остаётся гипотезой

1. Насколько хорошо Claude Code будет работать с Qodec на реальных задачах.
2. Каков реальный frontier между token saving и model readability.
3. Какие aliases минимизируют одновременно токены и путаницу.
4. Насколько сильно результат зависит от модели.
5. Какие части system/tool context допустимо сжимать.
6. Сможет ли online calibrator стабильно улучшать probe selection.
7. Насколько выигрыши сохраняются после смены модели или tokenizer.
8. Даст ли Qodec экономию всей agent session, а не только первого input.

---

19. Короткая продуктовая формулировка

Qodec следует позиционировать не как «суммаризатор контекста» и не как «магическое сокращение промптов».

Более точная формулировка:

«Qodec is a deterministic, byte-preserving and tokenizer-aware representation layer for structured LLM context. It independently verifies round-trip correctness, net token reduction and downstream behavioral preservation.»

По-русски:

«Qodec — детерминированный, сохраняющий байты и учитывающий токенизатор слой представления контекста для LLM. Корректность round-trip, чистая экономия токенов и сохранение поведения модели рассматриваются как независимые утверждения и доказываются разными методами.»

---

20. Главный принцип всей программы

Нельзя говорить:

«Qodec экономит 30% без потерь.»

Нужно говорить:

Byte round-trip:
    PASS

Net full-request token saving:
    30%

Model reconstruction:
    99.8%

Task pass-rate delta:
    -0.2 percentage points

Agent success delta:
    statistically inconclusive

Corpus:
    fixed and published

Model:
    exact identity recorded

Иными словами:

«Сначала определить, что именно считается потерей. Затем отдельно доказать отсутствие каждой такой потери.»

Именно это отличает инженерный результат от графика, где сначала печатают «65%», а потом с фонариком ищут, что именно измеряли.
