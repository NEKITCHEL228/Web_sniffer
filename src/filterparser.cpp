#include "filterparser.h"
#include "packet.h"
#include <vector>
#include <QStringList>
#include <QRegularExpression>
#include <stdexcept>
#include <QDebug>

enum class TokenType {
    FIELD, VALUE, EQ, NEQ, AND, OR, NOT, LPAREN, RPAREN, END
};

struct Token {
    TokenType type;
    QString text;
};

class ConditionNode : public ASTNode {
    QString field;
    QString op;
    QString value;
public:
    ConditionNode(QString f, QString o, QString v) : field(f), op(o), value(v) {
        if (value.startsWith('"') && value.endsWith('"')) {
            value = value.mid(1, value.length() - 2);
        }
    }
    bool evaluate(std::shared_ptr<Packet> packet) const override {
        bool match = false;
        if (field == "ip.addr") {
            match = (packet->getSource() == value || packet->getDestination() == value);
        } else if (field == "ip.src") {
            match = (packet->getSource() == value);
        } else if (field == "ip.dst") {
            match = (packet->getDestination() == value);
        } else if (field == "time") {
            match = (packet->getTime() == value);
        } else if (field == "ip.proto") {
            match = (packet->getProtocol().compare(value, Qt::CaseInsensitive) == 0);
        } else if (field == "tcp.port" || field == "udp.port") {
            QString prot = packet->getProtocol().toLower();
            if ((field == "tcp.port" && prot == "tcp") || (field == "udp.port" && prot == "udp")) {
                bool ok;
                uint16_t port = value.toUShort(&ok);
                if (ok) {
                    match = (packet->getSrcPort() == port || packet->getDestPort() == port);
                }
            }
        } else if (field == "tcp.srcport" || field == "udp.srcport" || field == "tsp.srcport") {
            QString prot = packet->getProtocol().toLower();
            if ((field.contains("tcp") && prot == "tcp") || (field.contains("tsp") && prot == "tcp") || (field.contains("udp") && prot == "udp")) {
                bool ok;
                uint16_t port = value.toUShort(&ok);
                if (ok) {
                    match = (packet->getSrcPort() == port);
                }
            }
        } else if (field == "tcp.dstport" || field == "udp.dstport") {
            QString prot = packet->getProtocol().toLower();
            if ((field.contains("tcp") && prot == "tcp") || (field.contains("udp") && prot == "udp")) {
                bool ok;
                uint16_t port = value.toUShort(&ok);
                if (ok) {
                    match = (packet->getDestPort() == port);
                }
            }
        }

        if (op == "!=") return !match;
        return match;
    }
};

class LogicalNode : public ASTNode {
    QString op;
    std::shared_ptr<ASTNode> left;
    std::shared_ptr<ASTNode> right;
public:
    LogicalNode(QString o, std::shared_ptr<ASTNode> l, std::shared_ptr<ASTNode> r) : op(o), left(l), right(r) {}
    bool evaluate(std::shared_ptr<Packet> packet) const override {
        if (!left || !right) return false;
        if (op == "&&" || op == "and") {
            return left->evaluate(packet) && right->evaluate(packet);
        } else if (op == "||" || op == "or") {
            return left->evaluate(packet) || right->evaluate(packet);
        }
        return false;
    }
};

class NotNode : public ASTNode {
    std::shared_ptr<ASTNode> expr;
public:
    NotNode(std::shared_ptr<ASTNode> e) : expr(e) {}
    bool evaluate(std::shared_ptr<Packet> packet) const override {
        if (!expr) return false;
        return !expr->evaluate(packet);
    }
};

class Parser {
    std::vector<Token> tokens;
    size_t pos = 0;

public:
    Parser(const std::vector<Token>& t) : tokens(t) {}

    std::shared_ptr<ASTNode> parse() {
        if (tokens.empty() || tokens[0].type == TokenType::END) return nullptr;
        return parseOr();
    }

private:
    Token current() {
        if (pos < tokens.size()) return tokens[pos];
        return {TokenType::END, ""};
    }

    void advance() {
        if (pos < tokens.size()) pos++;
    }

    std::shared_ptr<ASTNode> parseOr() {
        auto left = parseAnd();
        while (current().type == TokenType::OR) {
            QString op = current().text;
            advance();
            auto right = parseAnd();
            left = std::make_shared<LogicalNode>(op, left, right);
        }
        return left;
    }

    std::shared_ptr<ASTNode> parseAnd() {
        auto left = parseNot();
        while (current().type == TokenType::AND) {
            QString op = current().text;
            advance();
            auto right = parseNot();
            left = std::make_shared<LogicalNode>(op, left, right);
        }
        return left;
    }

    std::shared_ptr<ASTNode> parseNot() {
        if (current().type == TokenType::NOT) {
            advance();
            return std::make_shared<NotNode>(parseNot());
        }
        return parsePrimary();
    }

    std::shared_ptr<ASTNode> parsePrimary() {
        if (current().type == TokenType::LPAREN) {
            advance();
            auto expr = parseOr();
            if (current().type == TokenType::RPAREN) {
                advance();
            }
            return expr;
        }

        if (current().type == TokenType::FIELD) {
            QString field = current().text;
            advance();
            if (current().type == TokenType::EQ || current().type == TokenType::NEQ) {
                QString op = current().text;
                advance();
                if (current().type == TokenType::VALUE || current().type == TokenType::FIELD) {
                    QString val = current().text;
                    advance();
                    return std::make_shared<ConditionNode>(field, op, val);
                }
            } else {
                return std::make_shared<ConditionNode>(field, "==", "");
            }
        }

        if (current().type != TokenType::END) {
            advance();
            return std::make_shared<ConditionNode>("", "==", "");
        }

        return nullptr;
    }
};

std::shared_ptr<ASTNode> FilterParser::parse(const QString& query) {
    if (query.trimmed().isEmpty()) return nullptr;

    std::vector<Token> tokens;

    QRegularExpression re(
        "\\s*(?:(==|!=|&&|\\|\\||!|\\(|\\))|"
        "(and|or|not)\\b|"
        "([a-zA-Z0-9_\\.:]+)|"
        "(\"[^\"]*\"))\\s*", QRegularExpression::CaseInsensitiveOption);

    QRegularExpressionMatchIterator i = re.globalMatch(query);
    while (i.hasNext()) {
        QRegularExpressionMatch match = i.next();
        QString op = match.captured(1);
        QString kw = match.captured(2).toLower();
        QString ident = match.captured(3);
        QString str = match.captured(4);

        if (!op.isEmpty()) {
            if (op == "==") tokens.push_back({TokenType::EQ, op});
            else if (op == "!=") tokens.push_back({TokenType::NEQ, op});
            else if (op == "&&") tokens.push_back({TokenType::AND, op});
            else if (op == "||") tokens.push_back({TokenType::OR, op});
            else if (op == "!") tokens.push_back({TokenType::NOT, op});
            else if (op == "(") tokens.push_back({TokenType::LPAREN, op});
            else if (op == ")") tokens.push_back({TokenType::RPAREN, op});
        } else if (!kw.isEmpty()) {
            if (kw == "and") tokens.push_back({TokenType::AND, kw});
            else if (kw == "or") tokens.push_back({TokenType::OR, kw});
            else if (kw == "not") tokens.push_back({TokenType::NOT, kw});
        } else if (!ident.isEmpty()) {
            ident = ident.toLower();
            if (ident.startsWith("ip.") || ident.startsWith("tcp.") || ident.startsWith("udp.") || ident.startsWith("tsp.") || ident == "time") {
                tokens.push_back({TokenType::FIELD, ident});
            } else {
                tokens.push_back({TokenType::VALUE, match.captured(3)});
            }
        } else if (!str.isEmpty()) {
            tokens.push_back({TokenType::VALUE, str});
        }
    }

    tokens.push_back({TokenType::END, ""});

    Parser parser(tokens);
    try {
        return parser.parse();
    } catch (...) {
        return nullptr;
    }
}
