#ifndef FILTERPARSER_H
#define FILTERPARSER_H

#include <QString>
#include <memory>

class Packet;

class ASTNode {
public:
    virtual bool evaluate(std::shared_ptr<Packet> packet) const = 0;
    virtual ~ASTNode() = default;
};

class FilterParser {
public:
    static std::shared_ptr<ASTNode> parse(const QString& query);
};

#endif // FILTERPARSER_H
