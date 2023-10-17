/*
 * Copyright (C) 2023 Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

package test

const PickOne = `
{
  "submission_requirements": [
    {
      "name": "Pick 1 matcher",
      "rule": "pick",
      "count": 1,
      "from": "A"
    }
  ],
  "input_descriptors": [
	{
	  "name": "Pick 1",
      "group": ["A"],
	  "constraints": {
		"fields": [
		  {
			"path": [
			  "$.id"
			],
			"filter": {
			  "type": "string",
			  "const": "1"
			}
		  }
		]
	  }
    },
    {
	  "name": "Pick 2",
      "group": ["A"],
	  "constraints": {
		"fields": [
		  {
			"path": [
			  "$.id"
			],
			"filter": {
			  "type": "string",
			  "const": "2"
			}
		  }
		]
	  }
    }	
  ]
}
`

const PickMinMax = `
{
  "submission_requirements": [
    {
      "name": "Pick 1 matcher",
      "rule": "pick",
      "max": 2,
      "min": 1,
      "from": "A"
    }
  ],
  "input_descriptors": [
	{
	  "name": "Pick 1",
      "group": ["A"],
	  "constraints": {
		"fields": [
		  {
			"path": [
			  "$.id"
			],
			"filter": {
			  "type": "string",
			  "const": "1"
			}
		  }
		]
	  }
    },
    {
	  "name": "Pick 2",
      "group": ["A"],
	  "constraints": {
		"fields": [
		  {
			"path": [
			  "$.id"
			],
			"filter": {
			  "type": "string",
			  "const": "2"
			}
		  }
		]
	  }
    }	
  ]
}
`

const PickOnePerGroup = `
{
  "submission_requirements": [
    {
      "name": "Pick 1 from A",
      "rule": "pick",
      "count": 1,
      "from": "A"
    },
    {
      "name": "Pick 1 from B",
      "rule": "pick",
      "count": 1,
      "from": "B"
    }
  ],
  "input_descriptors": [
	{
	  "name": "Pick 1",
      "group": ["A"],
	  "constraints": {
		"fields": [
		  {
			"path": [
			  "$.id"
			],
			"filter": {
			  "type": "string",
			  "const": "1"
			}
		  }
		]
	  }
    },
    {
	  "name": "Pick 1",
      "group": ["B"],
	  "constraints": {
		"fields": [
		  {
			"path": [
			  "$.id"
			],
			"filter": {
			  "type": "string",
			  "const": "2"
			}
		  }
		]
	  }
    }	
  ]
}
`

const All = `
{
  "submission_requirements": [
    {
      "name": "All matcher",
      "rule": "all",
      "from": "A"
    }
  ],
  "input_descriptors": [
	{
<<<<<<< HEAD
	  "name": "Match ID=1",
=======
	  "name": "Pick",
>>>>>>> 78a08ad4 (some basic all and pick rules working for selecting VCs)
      "group": ["A"],
	  "constraints": {
		"fields": [
		  {
			"path": [
			  "$.id"
			],
			"filter": {
			  "type": "string",
			  "const": "1"
			}
		  }
		]
	  }
    },
    {
<<<<<<< HEAD
	  "name": "Match ID=2",
=======
	  "name": "Pick",
>>>>>>> 78a08ad4 (some basic all and pick rules working for selecting VCs)
      "group": ["A"],
	  "constraints": {
		"fields": [
		  {
			"path": [
			  "$.id"
			],
			"filter": {
			  "type": "string",
			  "const": "2"
			}
		  }
		]
	  }
    }	
  ]
}
`

const PickOneFromNested = `
{
  "submission_requirements": [
    {
      "name": "Pick 1 matcher",
      "rule": "pick",
      "count": 1,
      "from_nested": [
        {
          "name": "All A matcher",
          "rule": "all",
          "from": "A"
        },
        {
          "name": "All B matcher",
          "rule": "all",
          "from": "B"
        }
      ]
    }
  ],
  "input_descriptors": [
	{
	  "name": "Match ID=1",
      "group": ["A"],
	  "constraints": {
		"fields": [
		  {
			"path": [
			  "$.id"
			],
			"filter": {
			  "type": "string",
			  "const": "1"
			}
		  }
		]
	  }
    },
    {
	  "name": "Match ID=2",
      "group": ["A"],
	  "constraints": {
		"fields": [
		  {
			"path": [
			  "$.id"
			],
			"filter": {
			  "type": "string",
			  "const": "2"
			}
		  }
		]
	  }
    },
    {
	  "name": "Match ID=3",
      "group": ["B"],
	  "constraints": {
		"fields": [
		  {
			"path": [
			  "$.id"
			],
			"filter": {
			  "type": "string",
			  "const": "3"
			}
		  }
		]
	  }
    },
    {
	  "name": "Match ID=4",
      "group": ["B"],
	  "constraints": {
		"fields": [
		  {
			"path": [
			  "$.id"
			],
			"filter": {
			  "type": "string",
			  "const": "4"
			}
		  }
		]
	  }
    }
  ]
}
`

const AllFromNested = `
{
  "submission_requirements": [
    {
      "name": "All from nested",
      "rule": "all",
      "from_nested": [
        {
          "name": "All A matcher",
          "rule": "all",
          "from": "A"
        },
        {
          "name": "All B matcher",
          "rule": "all",
          "from": "B"
        }
      ]
    }
  ],
  "input_descriptors": [
	{
	  "name": "Match ID=1",
      "group": ["A"],
	  "constraints": {
		"fields": [
		  {
			"path": [
			  "$.id"
			],
			"filter": {
			  "type": "string",
			  "const": "1"
			}
		  }
		]
	  }
    },
    {
	  "name": "Match ID=2",
      "group": ["B"],
	  "constraints": {
		"fields": [
		  {
			"path": [
			  "$.id"
			],
			"filter": {
			  "type": "string",
			  "const": "2"
			}
		  }
		]
	  }
    }
  ]
}
`

const PickMinMaxFromNested = `
{
  "submission_requirements": [
    {
      "name": "Pick 1 matcher",
      "rule": "pick",
      "min": 1,
	  "max": 2,
      "from_nested": [
        {
          "name": "All A matcher",
          "rule": "all",
          "from": "A"
        },
        {
          "name": "All B matcher",
          "rule": "all",
          "from": "B"
        },
        {
          "name": "All C matcher",
          "rule": "all",
          "from": "C"
        }
      ]
    }
  ],
  "input_descriptors": [
	{
	  "name": "Match ID=1",
      "group": ["A"],
	  "constraints": {
		"fields": [
		  {
			"path": [
			  "$.id"
			],
			"filter": {
			  "type": "string",
			  "const": "1"
			}
		  }
		]
	  }
    },
    {
	  "name": "Match ID=2",
      "group": ["B"],
	  "constraints": {
		"fields": [
		  {
			"path": [
			  "$.id"
			],
			"filter": {
			  "type": "string",
			  "const": "2"
			}
		  }
		]
	  }
    },
    {
	  "name": "Match ID=3",
      "group": ["C"],
	  "constraints": {
		"fields": [
		  {
			"path": [
			  "$.id"
			],
			"filter": {
			  "type": "string",
			  "const": "3"
			}
		  }
		]
	  }
    }
  ]
}
`

const DeduplicationRequired = `
{
  "submission_requirements": [
    {
      "name": "Both groups result in the same credential",
      "rule": "all",
      "from_nested": [
        {
          "name": "All A matcher",
          "rule": "all",
          "from": "A"
        },
        {
          "name": "All B matcher",
          "rule": "all",
          "from": "B"
        }
      ]
    }
  ],
  "input_descriptors": [
	{
	  "name": "Match ID=1",
      "group": ["A", "B"],
	  "constraints": {
		"fields": [
		  {
			"path": [
			  "$.id"
			],
			"filter": {
			  "type": "string",
			  "const": "1"
			}
		  }
		]
	  }
    }
  ]
}
`
