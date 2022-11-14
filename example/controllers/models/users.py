from typing import Optional,List

import cy_web
from example.controllers.models.tanents import Tanents
@cy_web.model()
class Users:

    # Tanent: Optional[Tanents]
    OldTanets:Optional[List[Tanents]]

