// Comprehensive unit tests for common/ module
// Tests: Result<T,E>, Base64, UniqueFD, StateJournal
#include <gtest/gtest.h>

#include "common/Result.hpp"
#include "common/Base64.hpp"
#include "common/UniqueFD.hpp"
#include "common/StateJournal.hpp"

#include <fstream>
#include <filesystem>

namespace fs = std::filesystem;

// =============================================================================
// Result<T, E> Tests
// =============================================================================

TEST(ResultTest, OkConstructionAndValueAccess) {
    neuro_mesh::Result<int, std::string> r(42);
    EXPECT_TRUE(r.ok());
    EXPECT_FALSE(r.is_err());
    EXPECT_EQ(r.value(), 42);
}

TEST(ResultTest, ErrConstructionAndErrorAccess) {
    neuro_mesh::Result<int, std::string> r(std::string("failure"));
    EXPECT_FALSE(r.ok());
    EXPECT_TRUE(r.is_err());
    EXPECT_EQ(r.error(), "failure");
}

TEST(ResultTest, UnwrapOrReturnsFallbackOnError) {
    neuro_mesh::Result<int, std::string> r(std::string("nope"));
    EXPECT_EQ(r.unwrap_or(99), 99);
}

TEST(ResultTest, UnwrapOrReturnsValueOnOk) {
    neuro_mesh::Result<int, std::string> r(42);
    EXPECT_EQ(r.unwrap_or(99), 42);
}

TEST(ResultTest, VoidSpecializationOk) {
    neuro_mesh::Result<void, std::string> r_ok;
    EXPECT_TRUE(r_ok.ok());
    EXPECT_FALSE(r_ok.is_err());
}

TEST(ResultTest, VoidSpecializationError) {
    neuro_mesh::Result<void, std::string> r_err(std::string("void error"));
    EXPECT_FALSE(r_err.ok());
    EXPECT_TRUE(r_err.is_err());
    EXPECT_EQ(r_err.error(), "void error");
}

// =============================================================================
// Base64 Tests
// =============================================================================

TEST(Base64Test, EncodeEmptyString) {
    EXPECT_EQ(neuro_mesh::base64_encode(""), "");
}

TEST(Base64Test, EncodeKnownVectors) {
    EXPECT_EQ(neuro_mesh::base64_encode("Man"), "TWFu");
    EXPECT_EQ(neuro_mesh::base64_encode("Ma"), "TWE=");
    EXPECT_EQ(neuro_mesh::base64_encode("M"), "TQ==");
}

TEST(Base64Test, Roundtrip) {
    std::string original = "Hello, World! This is a test string with 12345.";
    std::string encoded = neuro_mesh::base64_encode(original);
    std::string decoded = neuro_mesh::base64_decode(encoded);
    EXPECT_EQ(decoded, original);
}

TEST(Base64Test, RoundtripBinaryData) {
    std::string binary;
    for (int i = 0; i < 256; ++i) {
        binary += static_cast<char>(i);
    }
    std::string encoded = neuro_mesh::base64_encode(binary);
    std::string decoded = neuro_mesh::base64_decode(encoded);
    EXPECT_EQ(decoded, binary);
}

TEST(Base64Test, DecodeInvalidInputReturnsEmpty) {
    EXPECT_TRUE(neuro_mesh::base64_decode("!!!invalid!!!").empty());
}

TEST(Base64Test, EncodeDecodeWithPadding) {
    std::string s = "a";
    std::string enc = neuro_mesh::base64_encode(s);
    EXPECT_EQ(enc.back(), '=');
    EXPECT_EQ(neuro_mesh::base64_decode(enc), s);
}

TEST(Base64Test, DecodeIgnoresWhitespace) {
    std::string original = "Hello World";
    std::string encoded = neuro_mesh::base64_encode(original);
    std::string decoded = neuro_mesh::base64_decode(encoded);
    EXPECT_EQ(decoded, original);
}

// =============================================================================
// UniqueFD Tests
// =============================================================================

TEST(UniqueFDTest, DefaultConstruction) {
    neuro_mesh::UniqueFD fd;
    EXPECT_FALSE(fd.valid());
    EXPECT_EQ(fd.get(), -1);
}

TEST(UniqueFDTest, FromValidFd) {
    int pipefd[2];
    ASSERT_EQ(pipe(pipefd), 0);
    {
        neuro_mesh::UniqueFD fd(pipefd[0]);
        EXPECT_TRUE(fd.valid());
        EXPECT_EQ(fd.get(), pipefd[0]);
    }
    EXPECT_EQ(fcntl(pipefd[0], F_GETFD), -1);
    close(pipefd[1]);
}

TEST(UniqueFDTest, MoveSemantics) {
    int pipefd[2];
    ASSERT_EQ(pipe(pipefd), 0);
    neuro_mesh::UniqueFD fd1(pipefd[0]);
    EXPECT_TRUE(fd1.valid());

    neuro_mesh::UniqueFD fd2(std::move(fd1));
    EXPECT_FALSE(fd1.valid());
    EXPECT_TRUE(fd2.valid());
    EXPECT_EQ(fd2.get(), pipefd[0]);

    close(pipefd[1]);
}

TEST(UniqueFDTest, ReleaseDoesNotClose) {
    int pipefd[2];
    ASSERT_EQ(pipe(pipefd), 0);
    int released_fd;
    {
        neuro_mesh::UniqueFD fd(pipefd[0]);
        released_fd = fd.release();
        EXPECT_FALSE(fd.valid());
    }
    EXPECT_EQ(fcntl(released_fd, F_GETFD), 0);
    close(released_fd);
    close(pipefd[1]);
}

// =============================================================================
// StateJournal Tests
// =============================================================================

TEST(StateJournalTest, CreatesFileAndAppends) {
    std::string path = "/tmp/test_journal.log";
    std::remove(path.c_str());

    {
        neuro_mesh::StateJournal journal(path);
        uint64_t seq = journal.append("PRE_PREPARE", "TARGET", "{\"e\":1}");
        EXPECT_EQ(seq, 1);
    }

    std::ifstream in(path);
    ASSERT_TRUE(in.is_open());
    std::string line;
    std::getline(in, line);
    EXPECT_NE(line.find("\"seq\":1"), std::string::npos);
    EXPECT_NE(line.find("\"stage\":\"PRE_PREPARE\""), std::string::npos);
    EXPECT_NE(line.find("\"target\":\"TARGET\""), std::string::npos);

    std::remove(path.c_str());
}

TEST(StateJournalTest, RecoversSequenceNumber) {
    std::string path = "/tmp/test_journal_recovery.log";
    std::remove(path.c_str());

    {
        neuro_mesh::StateJournal journal(path);
        journal.append("PRE_PREPARE", "T", "{\"e\":1}");
        journal.append("COMMIT", "T", "{\"e\":2}");
        journal.append("EXECUTED", "T", "{\"e\":3}");
    }

    {
        neuro_mesh::StateJournal journal(path);
        EXPECT_EQ(journal.last_seq(), 3);
        uint64_t seq = journal.append("PREPARE", "T", "{\"e\":4}");
        EXPECT_EQ(seq, 4);
    }

    std::remove(path.c_str());
}

TEST(StateJournalTest, HandlesConcurrentWrites) {
    std::string path = "/tmp/test_journal_concurrent.log";
    std::remove(path.c_str());

    neuro_mesh::StateJournal journal(path);
    for (int i = 0; i < 100; ++i) {
        journal.append("TEST", "T", "{\"i\":" + std::to_string(i) + "}");
    }
    EXPECT_EQ(journal.last_seq(), 100);

    std::remove(path.c_str());
}

TEST(StateJournalTest, SequentialIds) {
    std::string path = "/tmp/test_journal_seq.log";
    std::remove(path.c_str());

    neuro_mesh::StateJournal journal(path);
    uint64_t s1 = journal.append("A", "T", "{}");
    uint64_t s2 = journal.append("B", "T", "{}");
    uint64_t s3 = journal.append("C", "T", "{}");

    EXPECT_EQ(s1, 1);
    EXPECT_EQ(s2, 2);
    EXPECT_EQ(s3, 3);

    std::remove(path.c_str());
}
