FROM public.ecr.aws/lambda/nodejs:20
COPY --chown=sbx_user1051:sbx_user1051 index.js ${LAMBDA_TASK_ROOT}/
USER sbx_user1051
CMD ["index.handler"]
