# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
from bumble import utils


# -----------------------------------------------------------------------------
def test_open_int_enums():
    class Foo(utils.OpenIntEnum):
        FOO = 1
        BAR = 2
        BLA = 3

    x = Foo(1)
    assert x.name == "FOO"
    assert x.value == 1
    assert int(x) == 1
    assert x == 1
    assert x + 1 == 2

    x = Foo(4)
    assert x.name == "Foo[4]"
    assert x.value == 4
    assert int(x) == 4
    assert x == 4
    assert x + 1 == 5

    print(list(Foo))


# -----------------------------------------------------------------------------
if __name__ == '__main__':
    test_open_int_enums()
