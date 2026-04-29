#include "filemanager.h"
#include <QFile>

FileManager* FileManager::instance = nullptr;

FileManager* FileManager::getInstance() {
    if (!instance) instance = new FileManager();
    return instance;
}

bool FileManager::saveToPcap(const QString &filename, const std::vector<std::shared_ptr<Packet>> &packets) {
    // Использование libpcap для записи заголовочного файла .pcap
    return true;
}

std::vector<std::shared_ptr<Packet>> FileManager::loadFromPcap(const QString &filename) {
    return {};
}
