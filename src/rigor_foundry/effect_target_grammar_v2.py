# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — shared target component grammar
"""Share the exact v2 identifier grammar across journal and clause targets."""

from __future__ import annotations

import re
from typing import Final

TARGET_VARIANT_V2: Final = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z")
