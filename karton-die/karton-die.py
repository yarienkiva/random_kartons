# IIRC this karton is a slightly modified version of
# https://github.com/raw-data/karton-die-classifier,
# can't remember what was changed though

from karton.core import Config, Karton, Task
import subprocess
import logging
import json
import re

log = logging.getLogger(__name__)


class DieClassifier(Karton):
    """
    Scan a given sample with Detect-It-Easy tool
    """

    identity = "karton.die"
    version = "1.0.0"
    filters = [{"type": "sample", "stage": "recognized"}]

    def __init__(
        self,
        config: Config = None,
        identity: str = None,
    ) -> None:
        super().__init__(config=config, identity=identity)

    def process_sample(self, sample_path: str) -> list:
        """Analyze a given sample

        Args:
            sample_path (str): path to file

        Returns:
            list: a list of tags consumable by MWDB
                  e.g. 
                        [ 
                            "die:library_.net_v4.0.30319",
                            "die:archive_rar_5",
                            "die:overlay_rar_archive"
                        ]
        """
        diec_res = subprocess.check_output(
            [
                "diec",
                "-j",
                sample_path,
            ]
        )
        try:
            diec_res_json = json.loads(diec_res)
        except Exception as err:
            self.log.error(err)
            return None
        else:
            print(diec_res_json)
            diec_mapping: dict = {
                "compiler": None,
                "archive": None,
                "protector": None,
                "installer": None,
                "overlay": None,
                "sfx": None,
                "library": None,
                "packer": None,
            }

            if not len(diec_res_json["detects"]):
                return None

            if "values" not in diec_res_json["detects"][0]:
                return None

            for entry in diec_res_json["detects"][0]["values"]:
                for field, result in diec_mapping.items():
                    if entry.get("type").lower() == field:
                        diec_mapping[field] = entry["name"].lower().replace(' ','-')

            signature_matches = list()
            for field, result in diec_mapping.items():
                if result:
                    signature_matches.append(f"die:{field}_{result}")

            return signature_matches

    def process(self, task: Task) -> None:
        sample = task.get_resource("sample")
        if task.headers["type"] == "sample":
            self.log.info(f"Hello sample {sample.metadata['sha256']}, it's 4AM time for your processing")
            with sample.download_temporary_file() as f:
                sample_path = f.name
                die_signatures: list = self.process_sample(sample_path)
                print(die_signatures)

        if not die_signatures:
            self.log.info("Could not match signatures")
            return None

        tag_task = Task(
            headers={"type": "sample", "stage": "analyzed"},
            payload={"sample": sample, "tags": die_signatures},
        )
        print(tag_task)

        self.send_task(tag_task)

if __name__ == "__main__":
    DieClassifier.main()
