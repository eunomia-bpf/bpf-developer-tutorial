# blog guideline or pattern

## Key Pattern and Requirements for eBPF Tutorial Blog Posts

### 1. **Title**

- Begin with a clear and descriptive title, following the format:

  ```
  # eBPF Tutorial by Example: [Topic Description]
  ```

  *Example:*

  ```
  # eBPF Tutorial by Example: Recording TCP Connection Status and TCP RTT
  ```

- Or slightly different

  ```
  # eBPF Developer Tutorial: [Topic Description]
  ```

### 2. **Introduction** and background

- Start with a brief introduction to eBPF, explaining its significance and capabilities.
- Provide context for the tutorial's focus, mentioning the specific tools, example or use cases that will be covered.
- **Goal:** Help readers understand what they will learn and why it's important.

### 3. **Overview of the Tools, Examples or features or what we are describing in this tutorial**

Think of a better subtitle related to this part.

- Introduce the specific eBPF programs or tools that will be discussed.
- Explain their purpose and how they can help you, their usecase or why you need them.
- What key eBPF feature or kernel events is used or related? Only discuss important ones, but should be detailed
- **Goal:** Give readers a clear understanding of what each tool does.

Note that it might not always be a tool. Might be examples or others.

### 4. **Kernel eBPF Code Analysis**

- Present the kernel-mode eBPF code related to the tools.
- Include code snippets with proper formatting for readability.
  - if not too long, include the full code first.
- Provide detailed explanations of key sections in the code.
- for example:
  - *Define BPF Maps:* Explain the maps used and their purposes.
  - *Events:* Describe how the code attaches to kernel events.
  - *Logic:* Explain how the processing in kernel happens
  - *Features*: introduce used features in eBPF
- **Goal:** Help readers understand how the eBPF code works internally.

### 5. **User-Space Code Analysis**

- Present the user-space code that interacts with the eBPF program.
  - if not too long, include the full code first.
- Include code snippets and explain how the user-space application processes data from the eBPF program.
- for example:
  - *Event Handling:* Describe how events are received and processed.
  - *Data Presentation:* Explain how data is formatted and displayed to the user.
- **Goal:** Show how the eBPF program communicates with user-space and how to interpret the results.

### 6. **Compilation and Execution Instructions**

- Provide step-by-step instructions on how to compile and run the eBPF programs.
- Include commands and expected outputs.
- Mention any prerequisites or dependencies required.
  - *Compiling the eBPF Program:* Commands and explanations.
  - *Running the User-Space Application:* How to execute and interpret outputs.
- **Goal:** Enable readers to replicate the examples on their own systems.

You need to provide **Complete Source Code and Resources** link in ompilation and Execution Instructions.

- Provide links to the complete source code repositories.
- Include references to related tools, documentation, or tutorials.
  - *Source Code:* Direct links to GitHub or relevant repositories.
  - *References:* List of resources for further reading.
- **Goal:** Offer additional resources for readers to explore more deeply.

The repo is in <https://github.com/eunomia-bpf/bpf-developer-tutorial>, website at <https://eunomia.dev/tutorials/>. Typically you can run `make` in the related fir, such as `bpf-developer-tutorial/src/41-xdp-tcpdump` to build it.

### 7. **Summary and Conclusion**

- Summarize the key points covered in the tutorial.
- Emphasize the importance of the tools and concepts learned.
- Encourage readers to apply this knowledge and explore further.
- **Goal:** Reinforce learning outcomes and inspire continued learning.

You need to have **Call to Action** in Summary and Conclusion

- Invite readers to visit your tutorial repository and website for more examples and complete tutorials.
- Provide links to the main tutorial site and any relevant sections. The link should be show directly.

- **Example:**

  ```md
  If you would like to learn more about eBPF, visit our tutorial code repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or our website at <https://eunomia.dev/tutorials/>.
  ```

## Additional Guidelines

- **Consistency:** Maintain a consistent writing style and formatting across all blog posts.
- **Clarity:** Use clear and concise language to explain complex concepts.
- **Code Formatting:** Ensure all code snippets are properly formatted and syntax-highlighted for readability.
- **Visual Aids:** Include diagrams or charts if they help in explaining concepts better.
- **Audience Engagement:** Pose questions or scenarios that encourage readers to think and engage with the material.
- **Proofreading:** Check for grammatical errors and ensure technical accuracy.
- **Accessibility:** Make sure that the tutorials are accessible to readers with varying levels of expertise in eBPF.

Also, do not just list points, try to make it using paragraph unless points list is clear. 

The key point in tone: Using oral English, clear and simple words and short sentence, make it attractive and easy to read, do not make it like a paper. Not too much fancy words, try to be attracive.
