import unittest

import py3_hikvision.isc


class MyTestCase(unittest.TestCase):
    def test_something(self):
        isc=py3_hikvision.isc.ISC(
            host="https://202.97.177.91:1443",
            ak="21621175",
            sk="iL4J3BMF1qHObccHhEOu"
        )
        results=isc.request_with_signature(
            url=py3_hikvision.isc.RequestUrl.ARTEMIS_API_RESOURCE_V1_ORG_ORGLIST,
            json={"pageNo":1,"pageSize":100},
            verify=False,
        )
        print(results)
        self.assertTrue(True)


if __name__ == '__main__':
    unittest.main()
