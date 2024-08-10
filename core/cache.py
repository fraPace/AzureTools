import json
import logging
import os
import pickle

CACHE_FOLDER = os.path.join("cache")
CACHE_FILE_PATH = os.path.join(CACHE_FOLDER, "cache.json")


def dump_json(dataset, cache_file: str = CACHE_FILE_PATH, encoder=None):
    """
    Cache the dataset to a json format file.
    :param encoder:
    :param dataset:
    :param cache_file:
    """
    logger = logging.getLogger(__name__)

    logger.info("Caching data...")

    os.makedirs(os.path.dirname(cache_file), exist_ok=True)

    with open(cache_file, "w") as cache_file:
        if encoder:
            json.dump(dataset, cache_file, cls=encoder)
        else:
            json.dump(dataset, cache_file)

    logger.info(f"Successfully cached data to {cache_file}.")


def load_json(cache_file: str = CACHE_FILE_PATH, decoder=None):
    """
    Load the cached elements from a json file.
    :param decoder:
    :param cache_file:
    :return:
    """
    logger = logging.getLogger(__name__)

    logger.info(f"Loading cached elements from {cache_file}...")

    if os.path.exists(cache_file) and os.path.isfile(cache_file):
        with open(cache_file) as cache_file:
            if decoder:
                cache = json.load(cache_file, cls=decoder)
            else:
                cache = json.load(cache_file)
            logger.info(f"Successfully loaded the cached elements.")
            return cache
    else:
        logger.warning("No caches found.")

    return None


# Save the encoders to a file
def dump_pickle(data: object, cache_file: str):
    logger = logging.getLogger(__name__)

    logger.info("Caching data...")

    os.makedirs(os.path.dirname(cache_file), exist_ok=True)

    with open(cache_file, 'wb') as file:
        pickle.dump(data, file)

    logger.info(f"Successfully cached data to {cache_file}.")


# Load the encoders from a file
def load_pickle(cache_file: str):
    logger = logging.getLogger(__name__)

    logger.info(f"Loading cached elements from {cache_file}...")

    if os.path.exists(cache_file) and os.path.isfile(cache_file):
        with open(cache_file, 'rb') as file:
            object = pickle.load(file)
            logger.info(f"Successfully loaded the cached elements.")
            return object
    else:
        logger.warning("No caches found.")

    return None
