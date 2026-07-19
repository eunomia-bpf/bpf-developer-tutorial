# Blog Guidelines for Advanced eBPF Tutorials

This document outlines the key patterns and requirements for writing advanced eBPF tutorials. Advanced tutorials focus on complex eBPF programs, tools, or features that extend beyond basic concepts. They require a deeper understanding of eBPF and kernel interactions.

The audience for advanced tutorials includes developers, system administrators, and security professionals with intermediate to advanced eBPF knowledge. The goal is to provide in-depth explanations of advanced eBPF topics and practical examples that readers can apply in real-world scenarios.

The key point in tone: Using oral English, clear and simple words and short sentence, make it attractive and easy to read, do not make it like a paper. Not too much fancy words, try to be attracive.

You should also include all the details and information I provide to you. do not simplify or change any of them, you just need to regorganize them in a more attractive way as a tutorial blog.

## starting with a clear and descriptive title

Begin with a clear and descriptive title:

```
# eBPF Tutorial by Example: [Advanced Topic]
```

Kick off with a brief intro to the advanced eBPF topic you're covering, and the example or tool you'll discuss. Highlight its significance and how it extends beyond basic concepts. Let readers know what they'll learn and why it's important.

## Incroduction to the concept, tool and Background

(Come up with a better session title)

Provide an overview of the specific eBPF programs, tools, or features you'll discuss. Explain their purpose, use cases, and the key eBPF features or kernel events involved. Focus on aspects that are crucial for advanced understanding.

## High-Level Code Analysis

Dive into the kernel-mode eBPF code and user-space code, focusing on high-level concepts rather than basic syntax.

Always include the full code as it is first. then break down the key parts.

Try to avoid using too much list, make it more like a story.

Follow the steps:

1. First, introduce The overall processing logic in both kernel and user space.
2. Then break down the kernel-mode eBPF code, include

- How the eBPF program is structured.
- Key eBPF functionalities utilized.
- How the code interacts with kernel events.

Do not make them a list, make them some paragraphs, you can also quote some code snippets to explain the key parts of the code if needed, focus on the logic and features used in advanced eBPF development. Don't make it too long, but make sure it is informative enough and you explain everything a advanced eBPF developer wants to know.

3. Then briefly explain the user-space code

Aim to help readers grasp how the code works without getting bogged down in basic details.

## Any more detailed concepts or features explanation

If there are other information or features that are important to understand the code, you can add them here.

## 5. Compilation and Execution

Provide instructions on compiling and running the eBPF programs, noting any advanced configurations or dependencies. Include commands and what readers should expect as output. Typically, you can run `make` in the relevant directory in the tutorial repository to build the code.

Include links to complete source code and resources:

- **Repository:** <https://github.com/eunomia-bpf/bpf-developer-tutorial>
- **Website:** <https://eunomia.dev/tutorials/>

## 6. Summary and Call to Action

Wrap up by summarizing the key points. Emphasize the advanced concepts covered and encourage readers to apply this knowledge. Invite them to explore more examples and tutorials, as one paragraph:

> If you'd like to dive deeper into eBPF, check out our tutorial repository at <https://github.com/eunomia-bpf/bpf-developer-tutorial> or visit our website at <https://eunomia.dev/tutorials/>.

## reference

You should include the important references and resources that used in the tutorial. If this is from other sources like kernel sample or tools, make sure to include them here and clearly mention them in the tutorial.

## Additional Guidelines

- **Clarity:** Use simple language and short sentences to explain complex ideas. But the information should be complete and detailed.
- **Focus on Advanced Concepts:** Assume readers have basic eBPF knowledge; skip elementary explanations.
- **Engagement:** Encourage readers to think critically and engage with the material.
- **Consistency:** Keep a consistent style and formatting throughout.
- **Code Formatting:** Ensure code snippets are well-formatted and highlight key parts. Do not change or simplify any of the code and commands, keep them as they are.
- **Proofreading:** Double-check for errors and ensure technical accuracy.
- **Accessibility:** Make the content valuable for readers with advanced expertise, avoiding unnecessary simplifications.
