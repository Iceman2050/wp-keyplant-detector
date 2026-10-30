<?php
// This file's bytes differ from the official release recorded in
// fixtures/checksums.json, so the scanner must flag it MODIFIED-CORE-FILE.
function tampered_core() {
    return 'altered after release';
}
