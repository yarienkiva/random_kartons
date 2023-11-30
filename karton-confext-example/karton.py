import tempfile
import logging
import os.path

from karton.core import Config, Karton, Task
from mwdblib import MWDB
import yara

# Custom imports


FAMILY    = 'FAMILY_NAME_IN_LOWERCASE' # has to respect the malpedia calling convention
YARA_RULE = None # None or '/path/to/rule.yar'

class Confextractor(Karton):
    
    """
    Confextractor for EXAMPLE.

    Example output:
    
    ```
    {
        ...
    }
    ```

    """

    identity = f"karton.confext.{FAMILY}"
    version = "0.1.0"
    filters = [{"type": "sample", "stage": "recognized"}]

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

    def check_tag(self, sample_hash: str) -> bool:
        """
        First, query the corresponding sample to `sample_hash` on the MWDB instance
        check if it contains FAMILY in its tags. 

        Args:
            sample_hash (str): The hash of the sample to check.

        Returns:
            bool: True if the sample has FAMILY in its tags, False otherwise.
        """

        mwdb_config = dict(self.config.config.items('mwdb'))

        api_key=mwdb_config.get("api_key")
        api_url=mwdb_config.get("api_url")

        mwdb = MWDB(api_key=api_key, api_url=api_url)

        if not api_key:
            mwdb.login(
                mwdb_config["username"],
                mwdb_config["password"])

        s = mwdb.query_file(sample_hash)
        return FAMILY in s.tags or "yara:{}".format(FAMILY) in s.tags

    def check_yara(self, sample_path: str) -> bool:
        """
        Check if a YARA rule matches a given sample path.

        Args:
            sample_path (str): The path of the sample to check.

        Returns:
            bool: True if the YARA rule matches the sample, False otherwise.
        """

        if not YARA_RULE:
            return False

        rule = yara.compile(YARA_RULE)
        return bool(rule.match(sample_path))

    def process(self, task: Task) -> None:
        """
        Process a given task by extracting configuration information from a sample.

        Args:
            task (Task): The task to process.

        Returns:
            None
        """

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
        """
        Extract configuration information from a given sample.

        Args:
            sample_path (str): The path of the sample to extract configuration information from.

        Returns:
            dict: A dictionary containing the extracted configuration information.
        """

        return dict()

if __name__ == "__main__":
    Confextractor().main()
