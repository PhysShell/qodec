# Secondary calibration: позиция и границы применения

> **Статус документа.** Авторская позиционная записка, зафиксирована
> 2026-07-25. Текст ниже — дословный; он не редактируется задним числом.
> Уточняет §4–5, §15 и §17 программы ([`docs/program.md`](program.md)):
> идея **отложена и резко сужена**, не отброшена.
>
> Состояние против кода на дату фиксации:
>
> * Production-переупорядочивание probes существует **до** этой записки и
>   **без shadow-стадии**: ranker `src/rank.rs` (`qodec train` →
>   `encode --profile --probe-budget`) переставляет и усечает очередь
>   кандидатов прямо в кодировании. Записка это исключение не легализует
>   задним числом — фиксируем его явно, с причиной, почему оно другого
>   класса риска, чем её calibrator: ranker обучается только офлайн, явным
>   `qodec train`, на точных *измеренных* gains (ровно тот «чистый корпус»,
>   который записка требует; никакого online-накопления из production и
>   никакого usage), включается вручную через `--profile`, а acceptance
>   остаётся измеренным — неверный ranker тратит probes, не байты
>   (измерено: cross-domain ranker деградирует до 9% recovery, оставаясь
>   byte-safe). Требование shadow-first применяется в полную силу к любому
>   будущему calibrator'у, обновляющемуся из production-наблюдений.
> * Из таблицы приоритетов: exact token meter, full-overhead accounting,
>   byte verifier — есть; paper/Qodec benchmark и frozen semantic
>   evaluation — закрыты milestone'ом
>   [`milestones/2026-07-25-lossless-program-e8815f0.md`](milestones/2026-07-25-lossless-program-e8815f0.md).
> * Shadow-mode calibrator — **не реализован** (следующая разрешённая
>   ступень); автоматический policy learner — significantly later;
>   обучение на общем Claude Code usage — **не делать** (панельные
>   envelope-записи в `evals/reader-cli/` подтвердили и практическую
>   сторону запрета: cache_read/creation делают cross-run сравнение
>   «fresh input» ненадёжным).
> * Предусловие к пункту о хранении канонического request (ревью PR #7):
>   до любой реализации такого сбора должны быть определены
>   privacy-контроли — минимизация/редакция чувствительного содержимого
>   (system prompt, история, tool results), сроки хранения, ограничение
>   доступа и процедура удаления. Сбор не реализован; ограничение
>   фиксируется здесь как обязательная часть его будущего дизайна.

---

Не отметаем. Откладываем и резко сужаем область применения. Иначе вторичная калибровка быстро превратится в умную систему, обученную на неправильной метрике. Человечество такое уже делало, обычно с дашбордом.

Итоговая позиция такая:

Что secondary calibration может делать

Она годится как вспомогательный слой перед точным измерением:

кандидаты кодирования
        ↓
первичная оценка стоимости/выигрыша
        ↓
secondary calibration
        ↓
порядок probes / shortlist
        ↓
точный tokenizer или count endpoint
        ↓
детерминированный выбор

То есть она может:

корректировать систематическую ошибку локального token estimator;

учитывать модель и tokenizer;

переупорядочивать кандидаты;

выбирать top-K для дорогого точного подсчёта;

замечать, что конкретный codec на данном типе данных обычно хуже прогноза;

адаптироваться к репозиторию, dialect или классу контента;

выявлять drift после смены модели или chat template.

Пример:

локальный estimator:
    mosaic = 4 200 токенов

официальный count:
    mosaic = 4 470 токенов

накопленная поправка для:
    Claude X × TypeScript × mosaic

secondary estimate:
    4 200 × 1.06 ≈ 4 452

Это нормальная online calibration.

Что она не должна делать

Она не должна:

принимать финальное решение вместо точного token meter;

определять losslessness;

заменять byte verifier;

обучаться на общем usage всей Claude Code-сессии;

автоматически заключать: «токенов потрачено больше, значит codec был плохой»;

оптимизировать agent outcome в текущем scope;

менять production policy сразу после нескольких наблюдений.

Главный запрет:

общий расход Claude Code
≠
стоимость Qodec payload

Там смешаны system prompt, tools, history, cache, ответы, retries и tool calls. Если обучать calibrator на такой метке, получится не calibration, а статистическая каша с уверенным API.

Где она находится относительно текущего плана

Сейчас

Текущий scope должен закрывать:

1. byte-exact round-trip;

2. детерминированное кодирование;

3. exact token accounting;

4. полный overhead словаря и decoder contract;

5. paper baseline;

6. frozen semantic benchmark;

7. строгий RAW/Qodec A/B.

Secondary calibration не нужна, чтобы доказать корректность или экономию.

Позже

После накопления чистого корпуса наблюдений:

candidate features
predicted token cost
exact token count
model identity
tokenizer identity
encoding plan
content class

можно добавить shadow-mode calibrator:

реальный выбор: A
calibrator предложил: B
production всё равно использует A
результат только записывается

Затем офлайн проверить:

уменьшается ли ошибка прогноза;

лучше ли top-K recall;

не пропускаются ли лучшие кандидаты;

насколько сокращается число probes;

стабильно ли это между корпусами;

что происходит после смены модели.

Только после этого разрешать ему переупорядочивать probes.

Минимальный безопасный дизайн

Входные признаки:

model_id
tokenizer_id
codec_id
payload_size_bucket
content_type
language
repetition_density
legend_size
alias_count
primary_estimate

Целевая величина:

exact_full_request_token_count

или, ещё чище:

exact_encoded_region_token_count

Выход:

corrected_token_estimate

Финальное решение всё равно такое:

точный count кандидатов
→ минимальная полная стоимость
→ byte verifier
→ accept

Что насчёт фактического usage после запроса

Его можно использовать для двух задач:

Полезно

проверить full-request estimator;

обнаружить изменение API-обвязки;

заметить tokenizer/model drift;

анализировать cache behavior;

сравнивать общую стоимость agent runs.

Нельзя напрямую

обновлять оценку отдельного codec;

приписывать всю разницу Qodec payload;

использовать как clean label без точного request snapshot.

Для обучения на production usage понадобится gateway или сохранённый канонический request, чтобы знать, что именно было отправлено.

Строгий вердикт

Идея остаётся хорошей, но это Phase после measurement infrastructure, а не часть lossless codec core.

Её место:

не в correctness path
не в acceptance oracle
не в decoder

а в:
candidate ranking
probe-budget optimization
token-estimate correction
drift detection

Приоритет я бы поставил такой:

Компонент	Приоритет

Exact token meter	обязательный
Full-overhead accounting	обязательный
Byte verifier	обязательный
Paper/Qodec benchmark	высокий
Frozen semantic evaluation	высокий
Secondary calibration в shadow mode	позже
Автоматический policy learner	значительно позже
Обучение по общему Claude Code usage	не делать

Так что идея не выброшена. Она просто лишилась права изображать из себя источник истины. И это ей только на пользу.
