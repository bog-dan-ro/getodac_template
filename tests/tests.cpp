/*
    Copyright (C) 2022 by BogDan Vatra <bogdan@kde.org>

    Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted.

    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

#include <EasyCurl.h>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

namespace {
using namespace std;
using json = nlohmann::json;

static string url{"http://localhost:8080/api/v1"};

TEST(MyCoolProjectTest, no_subjects)
{
    try {
        Getodac::Test::EasyCurl curl;
        EXPECT_NO_THROW(curl.setUrl(url + "/subjects"));
        auto reply = curl.get();
        EXPECT_EQ(reply.status, "200");
        EXPECT_EQ(reply.body, "[]");
    } catch(...) {
        EXPECT_NO_THROW(throw);
    }
}

TEST(MyCoolProjectTest, post_subject)
{
    try {
        Getodac::Test::EasyCurl curl;
        EXPECT_NO_THROW(curl.setUrl(url + "/subjects"));
        auto reply = curl.post(R"({"text": "First subject"})");
        EXPECT_EQ(reply.status, "200");
        EXPECT_EQ(reply.body, "");
        reply = curl.post(R"({"text": "Newer subject"})");
        EXPECT_EQ(reply.status, "200");
        EXPECT_EQ(reply.body, "");
    } catch (...) {
        EXPECT_NO_THROW(throw);
    }
}

TEST(MyCoolProjectTest, get_subjects)
{
    try {
        Getodac::Test::EasyCurl curl;
        EXPECT_NO_THROW(curl.setUrl(url + "/subjects"));
        auto reply = curl.get();
        EXPECT_EQ(reply.status, "200");
        auto j = json::parse(reply.body);
        EXPECT_EQ("Newer subject", j[0]["text"]);
        EXPECT_EQ("First subject", j[1]["text"]);
    } catch(...) {
        EXPECT_NO_THROW(throw);
    }
}

TEST(MyCoolProjectTest, add_replies)
{
    try {
        Getodac::Test::EasyCurl curl;
        EXPECT_NO_THROW(curl.setUrl(url + "/subjects"));
        auto reply = curl.get();
        EXPECT_EQ(reply.status, "200");
        auto j = json::parse(reply.body);
        EXPECT_EQ("Newer subject", j[0]["text"]);
        EXPECT_EQ("First subject", j[1]["text"]);
        EXPECT_NO_THROW(curl.setUrl(url + "/subjects/" + j[0]["id"].get<string>() + "/replies"));
        reply = curl.post(R"({"text": "First reply"})");
        EXPECT_EQ(reply.status, "200");
        EXPECT_EQ(reply.body, "");
        reply = curl.post(R"({"text": "Newer reply"})");
        EXPECT_EQ(reply.status, "200");
        EXPECT_EQ(reply.body, "");
        EXPECT_NO_THROW(curl.setUrl(url + "/subjects/" + j[1]["id"].get<string>() + "/replies"));
        reply = curl.post(R"({"text": "Another reply"})");
        EXPECT_EQ(reply.status, "200");
        EXPECT_EQ(reply.body, "");
        // at this point "First subject" is the first subject as it's the last one touched
    } catch (...) {
        EXPECT_NO_THROW(throw);
    }
}

TEST(MyCoolProjectTest, get_replies)
{
    try {
        Getodac::Test::EasyCurl curl;
        EXPECT_NO_THROW(curl.setUrl(url + "/subjects"));
        auto reply = curl.get();
        EXPECT_EQ(reply.status, "200");
        auto j = json::parse(reply.body);
        auto id0 = j[0]["id"].get<string>();
        auto id1 = j[1]["id"].get<string>();
        EXPECT_EQ("First subject", j[0]["text"]);
        EXPECT_EQ("Newer subject", j[1]["text"]);
        EXPECT_NO_THROW(curl.setUrl(url + "/subjects/" + id1 + "/replies"));
        reply = curl.get();
        EXPECT_EQ(reply.status, "200");
        j = json::parse(reply.body);
        EXPECT_EQ("Newer reply", j[0]["text"]);
        EXPECT_EQ("First reply", j[1]["text"]);
        EXPECT_NO_THROW(curl.setUrl(url + "/subjects/" + id0 + "/replies"));
        reply = curl.get();
        EXPECT_EQ(reply.status, "200");
        j = json::parse(reply.body);
        EXPECT_EQ("Another reply", j[0]["text"]);
        // at this point "Newer subject" is the first subject as it's the last one touched
    } catch (...) {
        EXPECT_NO_THROW(throw);
    }
}

TEST(MyCoolProjectTest, update_reply)
{
    try {
        Getodac::Test::EasyCurl curl;
        EXPECT_NO_THROW(curl.setUrl(url + "/subjects"));
        auto reply = curl.get();
        EXPECT_EQ(reply.status, "200");
        auto j = json::parse(reply.body);
        auto sid = j[1]["id"].get<string>();
        EXPECT_NO_THROW(curl.setUrl(url + "/subjects/" + sid + "/replies"));
        reply = curl.get();
        EXPECT_EQ(reply.status, "200");
        j = json::parse(reply.body);
        EXPECT_EQ(j.size(), 2);
        auto rid = j[1]["id"].get<string>();
        EXPECT_NO_THROW(curl.setUrl(url + "/subjects/" + sid + "/replies/" + rid));
        reply = curl.put("");
        EXPECT_EQ(reply.status, "200");
        EXPECT_EQ(reply.body, "");

        EXPECT_NO_THROW(curl.setUrl(url + "/subjects/" + sid + "/replies"));
        reply = curl.get();
        EXPECT_EQ(reply.status, "200");
        j = json::parse(reply.body);
        EXPECT_EQ(j.size(), 2);
        EXPECT_EQ(rid, j[0]["id"].get<string>());
    } catch (...) {
        EXPECT_NO_THROW(throw);
    }
}

} // namespace {
