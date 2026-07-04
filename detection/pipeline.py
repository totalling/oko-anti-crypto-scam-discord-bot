from dataclasses import dataclass, field

from config import Config
from detection import heuristics, ocr, phash_store


@dataclass
class ScanResult:
    is_scam: bool
    confidence: float
    reasons: list[str] = field(default_factory=list)
    hash_matched: bool = False
    image_hashes: list[str] = field(default_factory=list)


async def scan(text: str, image_bytes_list: list[bytes], cfg: Config) -> ScanResult:
    reasons: list[str] = []
    hash_matched = False
    hash_confidence = 0.0
    image_hashes: list[str] = []

    ocr_text_parts: list[str] = []
    for image_bytes in image_bytes_list:
        phash_hex = await phash_store.compute_phash(image_bytes)
        if phash_hex:
            image_hashes.append(phash_hex)
            match = await phash_store.find_closest_match(phash_hex, cfg.hash_distance_threshold)
            if match:
                hash_matched = True
                closeness = 1 - (match.distance / max(cfg.hash_distance_threshold, 1))
                hash_confidence = max(hash_confidence, 0.85 + 0.15 * closeness)
                reasons.append(f"matches known scam image (distance={match.distance}, source={match.source})")

        extracted = await ocr.extract_text(image_bytes, cfg)
        if extracted.strip():
            ocr_text_parts.append(extracted)

    combined_text = "\n".join([text, *ocr_text_parts])
    heuristic_result = heuristics.score_text(combined_text)
    reasons.extend(heuristic_result.reasons)

    confidence = max(hash_confidence, heuristic_result.score)
    is_scam = hash_matched or heuristic_result.score >= cfg.heuristic_auto_scam_score

    if is_scam and not hash_matched:
        for phash_hex in image_hashes:
            await phash_store.add_hash(phash_hex, source="auto:heuristic", added_by="bot")

    return ScanResult(
        is_scam=is_scam,
        confidence=confidence,
        reasons=reasons,
        hash_matched=hash_matched,
        image_hashes=image_hashes,
    )
