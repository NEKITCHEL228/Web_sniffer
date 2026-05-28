#1)Билд и тесты

#Выбор линукса на котором все будет идти
FROM ubuntu:22.04 AS builder

#Запрет на промпты пока идет установка
ENV DEBIAN_FRONTEND=noninteractive

#Установка зависимостей
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    git \
    qt6-base-dev \
    libqt6svg6-dev \
    libgl1-mesa-dev \
    libpcap-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

#Установка рабочей директории
WORKDIR /app

#Копируем туда весь проект
COPY . .

#Конфигурируем папку с релизом проекта
RUN rm -rf build && mkdir build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release .. && \
    make -j$(nproc)

#Запускаем тесты (QT_QPA_PLATFORM=offscreen предотвращает qt подключаться к серверу)
RUN cd build && \
    export QT_QPA_PLATFORM=offscreen && \
    ctest --output-on-failure --verbose

#2)Билд только исполняемого файла

#Выбор линукса на котором все будет идти
FROM ubuntu:22.04

#Запрет на промпты пока идет установка
ENV DEBIAN_FRONTEND=noninteractive

#Установка зависимостей (только необходимые библиотеки для запуска)
RUN apt-get update && apt-get install -y --no-install-recommends \
    qt6-base-dev \
    libqt6svg6 \
    libpcap0.8 \
    libgl1-mesa-glx \
    libglib2.0-0 \
    libdbus-1-3 \
    && rm -rf /var/lib/apt/lists/*

#Копируем исполняемый файл
COPY --from=builder /app/build/Web_Sniffer /usr/local/bin/Web_Sniffer

#Сетап платформы
ENV QT_QPA_PLATFORM=xcb

#Запускаем сниффер по дефолту
ENTRYPOINT ["/usr/local/bin/Web_Sniffer"]
