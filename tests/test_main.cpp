#include "../../../prebuilt/googletest/googletest/include/gtest/gtest.h"
#include "../../ad_logger/include/ad_logger.h"

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    ad_logger_init("../../../../configs/ad_zlog_config.conf");
    int ret = RUN_ALL_TESTS();
    ad_logger_fini();
    return ret;
}
