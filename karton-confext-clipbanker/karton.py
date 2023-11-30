import tempfile
import logging
import os.path

from karton.core import Config, Karton, Task
from mwdblib import MWDB
import yara

# Imports custom
from extractor import extract

FAMILY = 'clipbanker'
YARA_RULE = './rule.yar' # None ou '/path/to/rule.yar'

class Confextractor(Karton):

    """
    Confextractor for GenericClipper.

    Example output:

    ```
    {
      "ethereum": "0x9e60ca775c5c6c65e900795782be58e0de549615",
      "xmr": "8AFcmXsQttSXuBeYCL9fpa2rn5JrDwwoihMerrwF48V7Ar1EKNTZyGa6G2tMFMhEZNEReroTLe2gPSMQw6VZLSD65AyBqzD",
      "Mutexx": "pqdXXeEmLRGXHCg1",
      "startup": "yes",
      "btc": "1H8M6uYCSAquJuZjTjy33ruXs23hZy72E9",
      "url": "http://www.example.com/log.php",
      "ethereumE": "yes",
      "xmrE": "yes",
      "btcE": "yes"
    }
    ```

    """

    identity = f"karton.confext.{FAMILY}"
    version = "0.1.0"
    filters = [{"type": "sample", "stage": "recognized"}]

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

    def check_tag(self, file_hash: str) -> bool:
        mwdb_config = dict(self.config.config.items('mwdb'))
        api_key=mwdb_config.get("api_key")
        api_url=mwdb_config.get("api_url")

        mwdb = MWDB(api_key=api_key, api_url=api_url)
        if not api_key:
            mwdb.login(
                mwdb_config["username"],
                mwdb_config["password"])

        s = mwdb.query_file(file_hash)
        return FAMILY in s.tags or "yara:{}".format(FAMILY) in s.tags

    def check_yara(self, sample_path: str) -> bool:
        if not YARA_RULE:
            return False
        rule = yara.compile(YARA_RULE)
        return bool(rule.match(sample_path))

    def process(self, task: Task) -> None:
        sample = task.get_resource('sample')

        with tempfile.TemporaryDirectory() as tmpdir:
            sample_path = os.path.join(tmpdir, sample.sha256)
            sample.download_to_file(sample_path)

            # check tags on MWDB and yara rule (if provided)
            if not (self.check_tag(sample.sha256) or self.check_yara(sample_path)):
                logging.debug(f'Sample isn\'t a {FAMILY}, skipping')
                return

            try:
                conf = self.process_sample(sample_path)
                logging.info('Extracted config: ' + str(conf))
            except Exception as e:
                logging.warning('Could not extract config')
                logging.warning(e)
                return

            task = Task(
                {
                    "type":    "config",
                    "family":  FAMILY,
                    "kind":    "static",
                    "quality": "high"
                },
                payload = {
                    "config": conf,
                    "parent": sample
                }
            )
            self.send_task(task)

    def process_sample(self, sample_path: str) -> dict:
        return extract(sample_path)

if __name__ == "__main__":
    Confextractor().main()
