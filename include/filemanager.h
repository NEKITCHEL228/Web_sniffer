#ifndef FILEMANAGER_H
#define FILEMANAGER_H

#include "packet.h"
#include <vector>
#include <QString>

class FileManager {
public:
    static FileManager* getInstance();
    bool saveToPcap(const QString &filename, const std::vector<std::shared_ptr<Packet>> &packets);
    std::vector<std::shared_ptr<Packet>> loadFromPcap(const QString &filename);

private:
    FileManager() {}
    static FileManager* instance;
};

#endif
