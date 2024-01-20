/*
    Copyright (C) 2024 by BogDan Vatra <bogdan@kde.org>

    Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted.

    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

#include <iostream>
#include <memory>
#include <mutex>
#include <random>
#include <string>

#include <dracon/http.h>
#include <dracon/logging.h>
#include <dracon/restful.h>
#include <dracon/stream.h>
#include <dracon/utils.h>

#include <boost/algorithm/string.hpp>
#include <boost/property_tree/info_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <nlohmann/json.hpp>

#include <jwt-cpp/base.h>
#include <jwt-cpp/traits/nlohmann-json/traits.h>

using json = nlohmann::json;

TaggedLogger<> g_logger{"MyCoolProject"};

namespace {
uint32_t g_maxReplies = 100;

std::unique_ptr<jwt::algorithm::hs256> g_jwtAlgorithm;

Dracon::RESTfulRouterType g_restullV1RootNode("/api/v1/");
using Clock = std::chrono::system_clock;
using TimeStamp = std::chrono::time_point<Clock>;

struct Message
{
    Message(TimeStamp ts, const std::string &uuid, const std::string &msg)
        : timeStamp(ts)
    {
        message["id"] = uuid;
        message["text"] = msg;
        message["timestamp"] = timeStamp.time_since_epoch().count();
    }
    TimeStamp timeStamp;
    json message;
    void updateTimeStamp()
    {
        timeStamp = Clock::now();
        message["timestamp"] = timeStamp.time_since_epoch().count();
    }
};

class Replies : public Dracon::LruCache<std::string, Message>
{
public:
    Replies()
        : Dracon::LruCache<std::string, Message>(g_maxReplies) // no more than 100 replies for each subject
    {}
};

struct Subject : Message
{
    Subject(TimeStamp ts, const std::string &uuid, const std::string &msg)
        : Message(ts, uuid, msg)
    {}
    std::shared_ptr<Replies> replies = std::make_shared<Replies>();
    std::shared_ptr<std::mutex> mutex = std::make_shared<std::mutex>();
};


const std::string SubjectID{"subject"};
const std::string ReplyID{"reply"};

Dracon::LruCache<std::string, Subject> g_subjects{100}; // we keep up to 100 Subjects
std::mutex g_mutex;                                     // getodac is a highly concurrent HTTP server,
                                                        // therefore all resources must be protected properly
}

void authenticate(const Dracon::ParsedRoute & /*route*/, Dracon::AbstractStream &stream, Dracon::Request &req)
{
    stream >> req;
    const auto &auth = req.find("Authorization");
    if (auth == req.end())
        throw 401; // unauthorized
    auto tv = Dracon::split(auth->second, ' ');
    if (tv.size() != 2)
        throw Dracon::Response(400, "Invalid Authorization header");

    if (tv[0] != "Basic")
        throw Dracon::Response(401, "Logged user needed!", {{"WWW-Authenticate", "Basic"}});

    std::string authStr;
    try {
        authStr = jwt::base::decode<jwt::alphabet::base64>(tv[1].data());
    } catch (const std::exception &e) {
        throw Dracon::Response(400, e.what());
    } catch (...) {
        throw 400; // Bad request
    }

    auto userPass = Dracon::split(authStr, ':');
    if (userPass.size() != 2)
        throw Dracon::Response(400, "Invalid Authorization user:pass value");
}

void getSubjects(const Dracon::ParsedRoute & /*route*/, Dracon::AbstractStream &stream, Dracon::Request &req)
{
    // The request at this point is partial, next line will read the rest of the request
    stream >> req;

    json res = json::array();
    // as this function is use by both device and device/{device} routes
    // we need to check if we have the {device} resource and return the
    // appropriate results
    {
        std::unique_lock lock{g_mutex};
        for (const auto &subject : g_subjects)
            res.push_back(subject.second.message);
    } // don't keep the mutex locked while we're sending the data
    stream << Dracon::Response{200 /* res code */,
                               res.dump(), /* body */
                               {{"Content-Type","application/json"}} /* headers */
                              };
}

void postSubject(const Dracon::ParsedRoute &, Dracon::AbstractStream &stream, Dracon::Request &req)
{
    // The request at this point is partial,
    // next lines will read the rest of the request including the body
    std::string body;
    req.appendBodyCallback(
        [&](std::string_view buff) {
            body.append(buff);
            if (body.size() > 2048)
                throw 400; // bad request
        },
        2048);
    stream >> req;
    {
        auto jb = json::parse(body);
        auto uuid = boost::uuids::to_string(boost::uuids::random_generator()());
        std::unique_lock lock{g_mutex};
        g_subjects.put(uuid, Subject{Clock::now(), uuid, jb["text"]});
    } // don't keep the mutex locked while we're sending the data

    stream << Dracon::Response{200};
}

void getReplies(const Dracon::ParsedRoute &route, Dracon::AbstractStream &stream, Dracon::Request &req)
{
    // The request at this point is partial, next line will read the rest of the request
    stream >> req;

    // find the subject
    auto it = route.capturedResources.find(SubjectID);
    if (it == route.capturedResources.end())
        throw 404; // not found

    std::shared_ptr<Replies> replies;
    std::shared_ptr<std::mutex> mutex;
    {
        // we need to lock the mutex only for a short time
        std::unique_lock lock{g_mutex};
        if (!g_subjects.exists(it->second))
            throw 404; // not found
        const auto &subject = g_subjects.reference(it->second);
        replies = subject.replies;
        mutex = subject.mutex;
    }

    json res = json::array();
    if (mutex) {
        std::unique_lock lock{*mutex};
        for (const auto &reply : *replies)
            res.push_back(reply.second.message);
    } // don't keep the mutex locked while we're sending the data

    stream << Dracon::Response{
        200 /* res code */,
        res.dump(),                            /* body */
        {{"Content-Type", "application/json"}} /* headers */
    };
}

void postReply(const Dracon::ParsedRoute &route, Dracon::AbstractStream &stream, Dracon::Request &req)
{
    // The request at this point is partial,
    // next lines will read the rest of the request including the body
    std::string body;
    req.appendBodyCallback(
        [&](std::string_view buff) {
            body.append(buff);
            if (body.size() > 2048)
                throw 400; // bad request
        },
        2048);
    stream >> req;
    // find the subject
    auto it = route.capturedResources.find(SubjectID);
    if (it == route.capturedResources.end())
        throw 404; // not found

    std::shared_ptr<Replies> replies;
    std::shared_ptr<std::mutex> mutex;
    {
        // we need to lock the mutex only for a short time
        std::unique_lock lock{g_mutex};
        if (!g_subjects.exists(it->second))
            throw 404; // not found
        const auto &subject = g_subjects.reference(it->second);
        replies = subject.replies;
        mutex = subject.mutex;
    }

    {
        auto jb = json::parse(body);
        auto uuid = boost::uuids::to_string(boost::uuids::random_generator()());
        std::unique_lock lock{*mutex};
        replies->put(uuid, Message{Clock::now(), uuid, jb["text"]});
    } // don't keep the mutex locked while we're sending the data

    stream << Dracon::Response{200};
}

void updateReply(const Dracon::ParsedRoute &route, Dracon::AbstractStream &stream, Dracon::Request &req)
{
    // The request at this point is partial,
    // next lines will read the rest of the request including the body
    std::string body;
    req.appendBodyCallback(
        [&](std::string_view buff) {
            body.append(buff);
            if (body.size() > 2048)
                throw 400; // bad request
        },
        2048);
    stream >> req;
    // find the subject
    auto sit = route.capturedResources.find(SubjectID);
    if (sit == route.capturedResources.end())
        throw 404; // not found

    // find the reply
    auto rit = route.capturedResources.find(ReplyID);
    if (rit == route.capturedResources.end())
        throw 404; // not found

    std::shared_ptr<Replies> replies;
    std::shared_ptr<std::mutex> mutex;
    {
        // we need to lock the mutex only for a short time
        std::unique_lock lock{g_mutex};
        if (!g_subjects.exists(sit->second))
            throw 404; // not found

        const auto &subject = g_subjects.reference(sit->second);
        replies = subject.replies;
        mutex = subject.mutex;
    }

    {
        std::unique_lock lock{*mutex};
        if (!replies->exists(rit->second))
            throw 404; // not found

        auto &reply = replies->reference(rit->second);
        reply.updateTimeStamp();
    } // don't keep the mutex locked while we're sending the data

    stream << Dracon::Response{200};
}

PLUGIN_EXPORT bool init_plugin(const std::string &confDir)
{
    try {
        INFO(g_logger) << "Initializing REST API plugin ...";
        namespace pt = boost::property_tree;
        pt::ptree properties;
        const auto confPath = std::filesystem::path(confDir).append("MyCoolProject.conf");
        DEBUG(g_logger) << "Loading conf file from " << confPath;

        pt::read_info(confPath.string(), properties);
        std::string tokenSecret;
        tokenSecret = properties.get<std::string>("signing.secret");
        if (tokenSecret.empty()) {
            tokenSecret.resize(31);
            std::random_device rd;
            std::mt19937 gen(rd());
            std::generate(tokenSecret.begin(), tokenSecret.end(), gen);
        }
        g_jwtAlgorithm = std::make_unique<jwt::algorithm::hs256>(tokenSecret);

        g_subjects.cacheSize(properties.get<uint32_t>("emphemeral.max_subjects", 100));
        g_maxReplies = properties.get<uint32_t>("emphemeral.max_replies", 100);

        // v1 routes, here you can create highly complex routes.

        // authenticate
        g_restullV1RootNode.createRoute("authenticate")->addMethodHandler("GET", Dracon::sessionHandler(authenticate));

        // subjects
        g_restullV1RootNode.createRoute("subjects")
            ->addMethodHandler("GET", Dracon::sessionHandler(getSubjects))
            .addMethodHandler("POST", Dracon::sessionHandler(postSubject));

        // subjects/{subject}/replies
        g_restullV1RootNode.createRoute("subjects/{" + SubjectID + "}/replies")
            ->addMethodHandler("GET", Dracon::sessionHandler(getReplies))
            .addMethodHandler("POST", Dracon::sessionHandler(postReply));

        // subjects/{subject}/replies/{reply}
        g_restullV1RootNode.createRoute("subjects/{" + SubjectID + "}/replies/{" + ReplyID + "}")
            ->addMethodHandler("PUT", Dracon::sessionHandler(updateReply));

    } catch (const std::exception &e) {
        FATAL(g_logger) << e.what();
        return false;
    } catch (...) {
        FATAL(g_logger) << "Unknown fatal error";
        return false;
    }
    INFO(g_logger) << " ... completed";
    return true;
}

PLUGIN_EXPORT uint32_t plugin_order()
{
    // The server calls this function to get the plugin order
    return 0;
}

PLUGIN_EXPORT Dracon::HttpSession create_session(Dracon::Request &req)
{
    const auto &url = req.url();
    const auto &method = req.method();
    return g_restullV1RootNode.createHandler(url, method);
}

PLUGIN_EXPORT void destory_plugin()
{
    // This function is called by the server when it closes. The plugin should wait in this function until it finishes the clean up.
}
